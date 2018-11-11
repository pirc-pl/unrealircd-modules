#include "unrealircd.h"

#define BUFLEN 8191

// data file paths; place them in conf directory
#define IPv4PATH "GeoLite2-Country-Blocks-IPv4.csv"
#define COUNTRIESPATH "GeoLite2-Country-Locations-en.csv"
#define IPv6PATH "GeoLite2-Country-Blocks-IPv6.csv"

struct ip_range {
	uint32_t addr;
	uint32_t mask;
	int geoid;
	struct ip_range *next;
};

struct ip6_range {
	uint16_t addr[8];
	uint16_t mask[8];
	int geoid;
	struct ip6_range *next;
};

struct country {
	char code[10];
	char name[100];
	int id;
	struct country *next;
};

struct ip_range *ip_range_list[256]; // we are keeping a separate list for each possible first octet to speed up searching
struct ip6_range *ip6_range_list; // for ipv6 there would be too many separate lists so just use a single one
struct country *country_list;

// function declarations here
static int geoip_userconnect(aClient *);
static void free_ipv4(void);
static void free_ipv6(void);
static void free_countries(void);
static void free_all(void);
int hexval(char c);
static int read_ipv4(void);
static int ip6_convert(char *ip, uint16_t out[8]);
static int read_ipv6(void);
static int read_countries(void);
static struct country *get_country(int id);
static int get_v4_geoid(char *iip);
static int get_v6_geoid(char *iip);
static char *get_country_text(char *iip);

ModuleHeader MOD_HEADER(m_geoip_whois) = {
	"m_geoip_whois",
	"$Id: v1.03 2018/11/04 k4be$",
	"add country info to /whois", 
	"3.2-b8-1",
	NULL 
};

// functions for freeing allocated memory

static void free_ipv4(void){
	struct ip_range *ptr, *oldptr;
	int i;
	for(i=0; i<256; i++){
		ptr = ip_range_list[i];
		ip_range_list[i] = NULL;
		while(ptr){
			oldptr = ptr;
			ptr = ptr->next;
			MyFree(oldptr);
		}
	}
}

static void free_ipv6(void){
	struct ip6_range *ptr, *oldptr;
	ptr = ip6_range_list;
	ip6_range_list = NULL;
	while(ptr){
		oldptr = ptr;
		ptr = ptr->next;
		MyFree(oldptr);
	}
}

static void free_countries(void){
	struct country *ptr, *oldptr;
	ptr = country_list;
	country_list = NULL;
	while(ptr){
		oldptr = ptr;
		ptr = ptr->next;
		MyFree(oldptr);
	}
}

static void free_all(void){
	free_ipv4();
	free_ipv6();
	free_countries();
}

// convert hex digit to binary nibble

int hexval(char c){
	if(c >= '0' && c <= '9') return c-'0';
	if(c >= 'a' && c <= 'f') return c-'a'+10;
	if(c >= 'A' && c <= 'F') return c-'A'+10;
	return -1;
}

// reading data from files

static int read_ipv4(void){
	FILE *u;
	char buf[BUFLEN+1];
	int ip[4], cidr, geoid;
	uint32_t addr;
	uint32_t mask;
	struct ip_range *curr[256];
	struct ip_range *ptr;
	memset(curr, 0, sizeof(curr));
	int i;
	
	char *filename;
	filename = MyMallocEx(strlen(IPv4PATH) + 2);
	strcpy(filename, IPv4PATH);
	convert_to_absolute_path(&filename, CONFDIR);
	u = fopen(filename, "r");
	MyFree(filename);
	if(!u){
		sendto_realops("Cannot open IPv4 ranges list file\n");
		return 1;
	}
	
	if(!fgets(buf, BUFLEN, u)){
		sendto_realops("IPv4 list file is empty\n");
		return 1;
	}
	while(fscanf(u, "%d.%d.%d.%d/%d,%s", ip, ip+1, ip+2, ip+3, &cidr, buf) == 6){
		if(sscanf(buf, "%d,", &geoid) != 1){
	//		sendto_realops("Invalid or unsupported line in IPv4 ranges: %s\n", buf);
			continue;
		}
		for(i=0; i<4; i++){
			if(ip[i] < 0 || ip[i] > 255){
				sendto_realops("Invalid IP found! \"%d.%d.%d.%d\"\n", ip[0], ip[1], ip[2], ip[3]);
				continue;
			}
		}
		if(cidr < 1 || cidr > 32){
			sendto_realops("Invalid CIDR found! IP=%d.%d.%d.%d CIDR=%d\n", ip[0], ip[1], ip[2], ip[3], cidr);
			continue;
		}
		addr = ((uint32_t)(ip[0])) << 24 | ((uint32_t)(ip[1])) << 16 | ((uint32_t)(ip[2])) << 8 | ((uint32_t)(ip[3])); //convert address to a single number
		mask = 0;
		
		while(cidr){ // calculate netmask
			mask >>= 1;
			mask |= (1<<31);
			cidr--;
		}
		
		i=0;
		do { // multiple iterations in case CIDR is <8 and we have multiple first octets matching
			if(!curr[ip[0]]){
				ip_range_list[ip[0]] = MyMallocEx(sizeof(struct ip_range));
				curr[ip[0]] = ip_range_list[ip[0]];
			} else {
				curr[ip[0]]->next = MyMallocEx(sizeof(struct ip_range));
				curr[ip[0]] = curr[ip[0]]->next;
			}
			ptr = curr[ip[0]];
			ptr->next = NULL;
			ptr->addr = addr;
			ptr->mask = mask;
			ptr->geoid = geoid;
			i++;
			ip[0]++;
		} while(i<=((~mask)>>24));
	}
	fclose(u);
	return 0;
}

static int ip6_convert(char *ip, uint16_t out[8]){ // convert text to binary form
	int i=0, j, nib, word_pos=0, len;
	uint16_t word = 0;
	int nib_cnt = 0;
	memset(out, 0, 16);
	len = strlen(ip);
	for(;;){
		if(i == len || ip[i] == ':'){
			if(nib_cnt == 0){ // ::
				break;
			}
			out[word_pos] = word;
			word = 0;
			word_pos++;
			nib_cnt = 0;
			if(i == len) return 1; //already done
			if(word_pos > 7) return 0; //too long
		} else {
			if(nib_cnt == 4) return 0; // part is longer than 4 digits
			nib = hexval(ip[i]);
			if(nib < 0){
				//invalid addr
				return 0;
			}
			word <<= 4;
			word |= nib;
			nib_cnt++;
		}
		i++;
	}
	//now going from the end
	j = len-1;
	word = 0;
	word_pos = 7;
	nib_cnt = 0;
	for(;;){
		if(ip[j] == ':'){
			while(nib_cnt<4){
				word >>= 4;
				nib_cnt++;
			}
			out[word_pos] = word;
			word = 0;
			word_pos--;
			nib_cnt = 0;
			if(j == i) return 1; //done
		} else {
			if(nib_cnt == 4){
				return 0;
			}
			nib = hexval(ip[j]);
			if(nib < 0){
				return 0;
			}
			word >>= 4;
			word |= nib<<12;
			nib_cnt++;
		}
		j--;
	}
}

static int read_ipv6(void){
	FILE *u;
	char buf[BUFLEN+1];
	char *bptr, *optr;
	int cidr, geoid;
	char ip[40];
	uint16_t addr[8];
	uint16_t mask[8];
	struct ip6_range *curr = NULL;
	struct ip6_range *ptr;
	int error;

	char *filename;
	filename = MyMallocEx(strlen(IPv6PATH) + 2);
	strcpy(filename, IPv6PATH);
	convert_to_absolute_path(&filename, CONFDIR);
	u = fopen(filename, "r");
	MyFree(filename);
	if(!u){
		sendto_realops("Cannot open IPv6 ranges list file\n");
		return 1;
	}
	if(!fgets(buf, BUFLEN, u)){
		sendto_realops("IPv6 list file is empty\n");
		return 1;
	}
	while(fgets(buf, BUFLEN, u)){
		error = 0;
		bptr = buf;
		optr = ip;
		while(*bptr != '/'){
			if(!*bptr){
				error = 1;
				break;
			}
			*optr++ = *bptr++;
		}
		if(error) continue;
		*optr = '\0';
		bptr++;
		if(!ip6_convert(ip, addr)){
			sendto_realops("Invalid IP found! \"%s\"", ip);
			continue;
		}
		sscanf(bptr, "%d,%d,", &cidr, &geoid);
		if(cidr < 1 || cidr > 128){
			sendto_realops("Invalid CIDR found! CIDR=%d\n", cidr);
			continue;
		}

		memset(mask, 0, 16);
		
		int mask_bit = 0;
		while(cidr){ // calculate netmask
			mask[mask_bit/16] |= 1<<(15-(mask_bit%16));
			mask_bit++;
			cidr--;
		}

		if(!curr){
			ip6_range_list = MyMallocEx(sizeof(struct ip6_range));
			curr = ip6_range_list;
		} else {
			curr->next = MyMallocEx(sizeof(struct ip6_range));
			curr = curr->next;
		}
		ptr = curr;
		ptr->next = NULL;
		memcpy(ptr->addr, addr, 16);
		memcpy(ptr->mask, mask, 16);
		ptr->geoid = geoid;
	}
	fclose(u);
	return 0;

}

static int read_countries(void){
	FILE *u;
	char code[10];
	char name[100];
	char buf[BUFLEN+1];
	int i;
	int id;
	struct country *curr;
	
	char *filename;
	filename = MyMallocEx(strlen(COUNTRIESPATH) + 2);
	strcpy(filename, COUNTRIESPATH);
	convert_to_absolute_path(&filename, CONFDIR);
	u = fopen(filename, "r");
	MyFree(filename);
	if(!u){
		sendto_realops("Cannot open countries list file\n");
		return 1;
	}
	
	if(!fgets(buf, BUFLEN, u)){
		sendto_realops("Countries list file is empty\n");
		return 1;
	}
	while(fscanf(u, "%d,%[^\n]", &id, buf) == 2){ //getting country ID integer and all other data in string
		char *ptr = buf;
		char *optr = code;
		i=0;
		while(*ptr){
			if(i == 3){
				*optr = *ptr; // scan for country code (DE, PL, US etc)
				optr++;
			}
			ptr++;
			if(*ptr == ','){
				ptr++;
				i++;
				if(i == 4) break;
			}
		}
		*optr = '\0';
		optr = name;
		while(*ptr){
			*optr++ = *ptr++; // scan for country name
		}
		*optr = '\0';
		if(country_list){
			curr->next = MyMallocEx(sizeof(struct country));
			curr = curr->next;
		} else {
			country_list = MyMallocEx(sizeof(struct country));
			curr = country_list;
		}
		curr->next = NULL;
		strcpy(curr->code, code);
		strcpy(curr->name, name);
		curr->id = id;
		
	}
	fclose(u);
	return 0;
}

static struct country *get_country(int id){
	struct country *curr = country_list;
	if(!curr){
		sendto_realops("Countries list is empty! Try /rehash ing to fix\n");
		return NULL;
	}
	int found = 0;
	for(;curr;curr = curr->next){
		if(curr->id == id){
			found = 1;
			break;
		}
	}
	if(found) return curr;
	return NULL;
}

static int get_v4_geoid(char *iip){
	int ip[4];
	uint32_t addr, tmp_addr;
	struct ip_range *curr;
	int i;
	int found = 0;
	sscanf(iip, "%d.%d.%d.%d", ip, ip+1, ip+2, ip+3);
	for(i=0; i<4; i++){
		if(ip[i] < 0 || ip[i] > 255){
			sendto_realops("Invalid or unsupported client IP \"%s\"", iip);
			return 0;
		}
	}
	addr = ((uint32_t)(ip[0])) << 24 | ((uint32_t)(ip[1])) << 16 | ((uint32_t)(ip[2])) << 8 | ((uint32_t)(ip[3])); // convert IP to binary form
	curr = ip_range_list[ip[0]];
	if(curr){
		i = 0;
		for(;curr;curr = curr->next){
			tmp_addr = addr;
			tmp_addr &= curr->mask; // mask the address to filter out net prefix only
			if(tmp_addr == curr->addr){ // ... and match it to the loaded data
				found = 1;
				break;
			}
			if(found) break;
			i++;
		}
	}
	if(found) return curr->geoid;
	return 0;
}

static int get_v6_geoid(char *iip){
	uint16_t addr[8];
	struct ip6_range *curr;
	int i;
	int found = 0;
	
	if(!ip6_convert(iip, addr)){
		sendto_realops("Invalid or unsupported client IP \"%s\"", iip);
		return 0;
	}
	curr = ip6_range_list;
	if(curr){
		for(;curr;curr = curr->next){
			found = 1;
			for(i=0; i<8; i++){
				if(curr->addr[i] != (addr[i] & curr->mask[i])){ // compare net address to loaded data
					found = 0;
					break;
				}
			}
			if(found) break;
		}
	}
	if(found){
		return curr->geoid;
	}
	return 0;
}

static char *get_country_text(char *iip){
	int geoid;
	static char buf[BUFLEN];
	
	struct country *curr_country;
	
	if(!iip) return NULL;
	
	if(strchr(iip, ':')){ // IPV6 contains :, IPV4 does not
		geoid = get_v6_geoid(iip);
	} else {
		geoid = get_v4_geoid(iip);
	}
	if(geoid == 0) return NULL;
	curr_country = get_country(geoid);
	if(!curr_country) return NULL;
	sprintf(buf, "%s (%s)\n", curr_country->name, curr_country->code);
	return buf;
}

MOD_INIT(m_geoip_whois)
{
	HookAdd(modinfo->handle, HOOKTYPE_REMOTE_CONNECT, 0, geoip_userconnect);
	HookAdd(modinfo->handle, HOOKTYPE_LOCAL_CONNECT, 0, geoip_userconnect);
	return MOD_SUCCESS;
}

MOD_LOAD(m_geoip_whois)
{
	aClient *acptr;
	if(read_ipv4()){
		free_ipv4();
		return MOD_FAILED;
	}
	if(read_countries()){
		free_ipv4();
		free_countries();
		return MOD_FAILED;
	}
	if(read_ipv6()){
		free_ipv4();
		free_countries();
		free_ipv6();
		return MOD_FAILED;
	}
	list_for_each_entry(acptr, &client_list, client_node){
		if (!IsPerson(acptr)) continue;
		geoip_userconnect(acptr); // add info for all users upon module loading
	}
	return MOD_SUCCESS;
}

MOD_UNLOAD(m_geoip_whois)
{
	aClient *acptr;
	free_all();
	list_for_each_entry(acptr, &client_list, client_node){
		if (!IsPerson(acptr)) continue;
		swhois_delete(acptr, "geoip", "*", &me, NULL); // delete info when unloading 
	}
	return MOD_SUCCESS;
}

static int geoip_userconnect(aClient *cptr) {
	char *data = get_country_text(cptr->ip);
	if(!data) return HOOK_CONTINUE;
	char buf[BUFLEN+1];
	sprintf(buf, "connected from %s", data);
	swhois_delete(cptr, "geoip", "*", &me, NULL); //somehow has it already set
	swhois_add(cptr, "geoip", 0, buf, &me, NULL);
	return HOOK_CONTINUE;
}


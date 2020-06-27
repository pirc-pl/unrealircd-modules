/* Copyright (C) All Rights Reserved
** Written by k4be
** Website: https://github.com/pirc-pl/unrealircd-modules/
** License: GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
*/
 
 /*** <<<MODULE MANAGER START>>>
module
{
	documentation "https://github.com/pirc-pl/unrealircd-modules/blob/master/README.md#extjwt";
	troubleshooting "In case of problems, contact k4be on irc.pirc.pl.";
	min-unrealircd-version "5.*";
	post-install-text {
		"The module is installed. Now all you need to do is add a loadmodule line:";
		"loadmodule \"third/extjwt\";";
		"And create relevant config block, then /REHASH the IRCd.";
		"The configuration is described in the documentation:";
		"https://github.com/pirc-pl/unrealircd-modules/blob/master/README.md#extjwt";
	}
}
*** <<<MODULE MANAGER END>>>
*/

#include "unrealircd.h"

#define MSG_EXTJWT	"EXTJWT"
#define MYCONF "extjwt"

#define METHOD_NOT_SET 0
#define METHOD_HS256 1
#define METHOD_HS384 2
#define METHOD_HS512 3
#define METHOD_NONE 4

#define MODES_SIZE 41 // about 10 mode chars
#define TS_LENGTH 19 // 64-bit integer
#define MAX_TOKEN_CHUNK (510-sizeof(extjwt_message_pattern)-HOSTLEN-CHANNELLEN)
#define PAYLOAD_CHAN_SIZE (sizeof(payload_chan_pattern)+CHANNELLEN+TS_LENGTH+MODES_SIZE)
#define PAYLOAD_SIZE (sizeof(payload_pattern)+sizeof(payload_chan_pattern)+TS_LENGTH+HOSTLEN+NICKLEN+NICKLEN+MODES_SIZE+PAYLOAD_CHAN_SIZE)

CMD_FUNC(cmd_extjwt);
char *make_payload(Client *client, Channel *channel);
char *generate_token(const char *payload);
void b64url(char *b64);
unsigned char* hmac_hash(int method, const void *key, int keylen,
		const unsigned char *data, int datalen,
		unsigned char *result, unsigned int* resultlen);
const char *gen_header(int method);
int extjwt_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
int extjwt_configrun(ConfigFile *cf, ConfigEntry *ce, int type);
int extjwt_configposttest(int *errs);

const char extjwt_message_pattern[] = ":%s EXTJWT %s %s %s%s";
const char payload_pattern[] = "{\"exp\":%lu,\"iss\":\"%s\",\"sub\":\"%s\",\"account\":\"%s\",\"umodes\":[%s]%s}";
const char payload_chan_pattern[] = ",\"channel\":\"%s\",\"joined\":%lu,\"cmodes\":[%s]";

ModuleHeader MOD_HEADER = {
	"third/extjwt",
	"5.0test",
	"Command /EXTJWT (web service authorization)", 
	"k4be@PIRC",
	"unrealircd-5",
};

struct {
	time_t exp_delay;
	char *secret;
	int method;
	int have_secret;
	int have_method;
	int have_expire;
} cfg;

MOD_TEST(){
	safe_free(cfg.secret);
	memset(&cfg, 0, sizeof(cfg));
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, extjwt_configtest);
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGPOSTTEST, 0, extjwt_configposttest);
	return MOD_SUCCESS;
}

MOD_INIT(){
	CommandAdd(modinfo->handle, MSG_EXTJWT, cmd_extjwt, 2, CMD_USER);
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, extjwt_configrun);
	return MOD_SUCCESS;
}

MOD_LOAD(){
	ISupportAdd(modinfo->handle, "EXTJWT", "1");
	return MOD_SUCCESS;
}

MOD_UNLOAD(){
	return MOD_SUCCESS;
}

/*
extjwt {
	method "HS256"; // supported: HS256, HS384, HS512, NONE
	expire-after 30; // seconds
	secret "somepassword"; // do not set when METHOD "NONE"
}
*/

int extjwt_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs){
	int errors = 0;
	ConfigEntry *cep;
	int i;
	char *method = NULL;

	if (type != CONFIG_MAIN)
		return 0;

	if (!ce || strcmp(ce->ce_varname, MYCONF))
		return 0;

	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!cep->ce_vardata) {
			config_error("%s:%i: blank %s::%s without value", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
			errors++;
			continue;
		}
		if (!strcmp(cep->ce_varname, "method")) {
			if(cfg.have_method){
				config_error("%s:%i: duplicate %s:%s item", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
				errors++;
				continue;
			}
			if(!strcmp(cep->ce_vardata, "HS256")){
				cfg.have_method = METHOD_HS256;
				safe_strdup(method, cep->ce_vardata);
				continue;
			}
			if(!strcmp(cep->ce_vardata, "HS384")){
				cfg.have_method = METHOD_HS384;
				safe_strdup(method, cep->ce_vardata);
				continue;
			}
			if(!strcmp(cep->ce_vardata, "HS512")){
				cfg.have_method = METHOD_HS512;
				safe_strdup(method, cep->ce_vardata);
				continue;
			}
			if(!strcmp(cep->ce_vardata, "NONE")){
				cfg.have_method = METHOD_NONE;
				safe_strdup(method, cep->ce_vardata);
				continue;
			}
			config_error("%s:%i: invalid value %s::%s \"%s\"", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname, cep->ce_vardata);
			errors++;
		}
		if (!strcmp(cep->ce_varname, "expire-after")) {
			// Should be an integer yo
			for(i = 0; cep->ce_vardata[i]; i++) {
				if(!isdigit(cep->ce_vardata[i])) {
					config_error("%s:%i: %s::%s must be an integer between 1 and 9999 (seconds)", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
					errors++; // Increment err0r count fam
					break;
				}
			}
			if(!errors && (atoi(cep->ce_vardata) < 1 || atoi(cep->ce_vardata) > 9999)) {
				config_error("%s:%i: %s::%s must be an integer between 1 and 9999 (seconds)", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
				errors++; // Increment err0r count fam
			}
			continue;
		}
		if (!strcmp(cep->ce_varname, "secret")) {
			if(cfg.have_secret){
				config_error("%s:%i: duplicate %s:%s item", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
				errors++;
				continue;
			}
			if(strlen(cep->ce_vardata) < 4){
				config_error("%s:%i: Secret specified in %s::%s is too short!", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
				errors++; // Increment err0r count fam
			}
			cfg.have_secret = 1;
			continue;
		}
		config_error("%s:%i: unknown directive %s::%s", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
		errors++;
	}
	
	if(cfg.have_method != METHOD_NONE && !cfg.have_secret){
		config_error("No %s::secret specfied as required by the %s method!", MYCONF, method);
		errors++;
	}
	if(cfg.have_method == METHOD_NONE && cfg.have_secret){
		config_error("A %s::secret specfied but it should not be when using the %s method!", MYCONF, method);
		errors++;
	}

	*errs = errors;
	safe_free(method);
	return errors ? -1 : 1;
}

int extjwt_configposttest(int *errs) {
	int errors = 0;
	if(!cfg.have_method){
		config_error("Missing required %s::method option!", MYCONF);
		errors++;
	}
	if(!cfg.have_expire)
		cfg.exp_delay = 30; // default
	if(errors){
		*errs = errors;
		return -1;
	}
	return 1;
}

int extjwt_configrun(ConfigFile *cf, ConfigEntry *ce, int type){ // actually use the new configuration data
	ConfigEntry *cep;

	if (type != CONFIG_MAIN)
		return 0;

	if (!ce || strcmp(ce->ce_varname, MYCONF))
		return 0;

	for (cep = ce->ce_entries; cep; cep = cep->ce_next){
		if(!strcmp(cep->ce_varname, "method")){
			if(!strcmp(cep->ce_vardata, "HS256")){
				cfg.method = METHOD_HS256;
				continue;
			}
			if(!strcmp(cep->ce_vardata, "HS384")){
				cfg.method = METHOD_HS384;
				continue;
			}
			if(!strcmp(cep->ce_vardata, "HS512")){
				cfg.method = METHOD_HS512;
				continue;
			}
			if(!strcmp(cep->ce_vardata, "NONE")){
				cfg.method = METHOD_NONE;
				continue;
			}
		}
		if(!strcmp(cep->ce_varname, "expire-after"))
			cfg.exp_delay = atoi(cep->ce_vardata);
		if(!strcmp(cep->ce_varname, "secret"))
			cfg.secret = strdup(cep->ce_vardata);
	}
	return 1;
}

CMD_FUNC(cmd_extjwt){
	Channel *channel;
	char *payload;
	char *token, *full_token;
	int last = 0;
	char message[MAX_TOKEN_CHUNK+1];
	if(parc < 2 || BadPtr(parv[1])){
		sendnumeric(client, ERR_NEEDMOREPARAMS, MSG_EXTJWT);
		return;
	}
	if(parv[1][0] == '*' && parv[1][1] == '\0'){
		channel = NULL; // not linked to a channel
	} else {
		channel = find_channel(parv[1], NULL);
		if(!channel){
			sendnumeric(client, ERR_NOSUCHNICK, parv[1]);
			return;
		}
	}
	payload = make_payload(client, channel);
	if(!payload)
		return; // TODO error messages?
	full_token = generate_token(payload);
	if(!full_token)
		return;
	token = full_token;
	do {
		if(strlen(token) <= MAX_TOKEN_CHUNK){ // the remaining data (or whole token) will fit a single irc message
			last = 1;
			strcpy(message, token);
		} else { // send a chunk and shift buffer
			strlcpy(message, token, MAX_TOKEN_CHUNK+1);
			token += MAX_TOKEN_CHUNK;
		}
		sendto_one(client, NULL, extjwt_message_pattern, me.name, parv[1], "*", last?"":"* ", message);
	} while(!last);
	safe_free(full_token);
}

char *make_payload(Client *client, Channel *channel){
	static char payload[PAYLOAD_SIZE];
	char payload_channel[PAYLOAD_CHAN_SIZE];
	char modes[MODES_SIZE] = ""; // TODO fill with data
	Membership *lp;
	int array_empty;
	if(!IsUser(client))
		return NULL;
	if(channel){ // fill in channel information and user flags
		lp = find_membership_link(client->user->channel, channel);
		if(lp){
			array_empty = 1;
			if(lp->flags & CHFL_VOICE){
				strlcat(modes, "\"v\"", MODES_SIZE);
				array_empty = 0;
			}
			if(lp->flags & CHFL_HALFOP){
				if(!array_empty)
					strlcat(modes, ",", MODES_SIZE);
				strlcat(modes, "\"h\"", MODES_SIZE);
				array_empty = 0;
			}
			if(lp->flags & CHFL_CHANOP){
				if(!array_empty)
					strlcat(modes, ",", MODES_SIZE);
				strlcat(modes, "\"o\"", MODES_SIZE);
				array_empty = 0;
			}
#ifdef PREFIX_AQ
			if(lp->flags & CHFL_CHANADMIN){
				if(!array_empty)
					strlcat(modes, ",", MODES_SIZE);
				strlcat(modes, "\"a\"", MODES_SIZE);
				array_empty = 0;
			}
			if(lp->flags & CHFL_CHANOWNER){
				if(!array_empty)
					strlcat(modes, ",", MODES_SIZE);
				strlcat(modes, "\"q\"", MODES_SIZE);
				array_empty = 0;
			}
#endif
		}
		snprintf(payload_channel, PAYLOAD_CHAN_SIZE, payload_chan_pattern, channel->chname, (long unsigned int)(IsMember(client, channel)?1:0), modes);
	} else {
		payload_channel[0] = '\0';
	}
	modes[0] = '\0';
	if(IsOper(client)){ // add "o" ircop flag
		strcpy(modes, "\"o\"");
	}
	snprintf(payload, PAYLOAD_SIZE, payload_pattern, TStime()+cfg.exp_delay, me.name, client->name, (client->user->svid[0]=='0')?"":client->user->svid, modes, payload_channel);
	return payload;
}

void b64url(char *b64){ // convert base64 to base64-url
	while(*b64){
		if(*b64 == '+')
			*b64 = '-';
		if(*b64 == '/')
			*b64 = '_';
		if(*b64 == '='){
			*b64 = '\0';
			return;
		}
		b64++;
	}
}

unsigned char* hmac_hash(int method, const void *key, int keylen,
		const unsigned char *data, int datalen,
		unsigned char *result, unsigned int* resultlen){
	const EVP_MD* typ;
	switch(method){
		default:
		case METHOD_HS256:
			typ = EVP_sha256();
			break;
		case METHOD_HS384:
			typ = EVP_sha384();
			break;
		case METHOD_HS512:
			typ = EVP_sha512();
			break;
	}
	return HMAC(typ, key, keylen, data, datalen, result, resultlen); // openssl call
}

const char *gen_header(int method){ // returns header json
	switch(method){
		default:
		case METHOD_HS256:
			return "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
		case METHOD_HS384:
			return "{\"alg\":\"HS384\",\"typ\":\"JWT\"}";
		case METHOD_HS512:
			return "{\"alg\":\"HS512\",\"typ\":\"JWT\"}";
		case METHOD_NONE:
			return "{\"alg\":\"none\",\"typ\":\"JWT\"}";
	}
}

char *generate_token(const char *payload){
	const char *header = gen_header(cfg.method);
	size_t b64header_size = strlen(header)*4/3 + 8; // base64 has 4/3 overhead
	size_t b64payload_size = strlen(payload)*4/3 + 8;
	size_t b64sig_size = EVP_MAX_MD_SIZE*4/3 + 8;
	size_t b64data_size = b64header_size + b64payload_size + b64sig_size + 4;
	char *b64header = safe_alloc(b64header_size);
	char *b64payload = safe_alloc(b64payload_size);
	char *b64sig = safe_alloc(b64sig_size);
	char *b64data = safe_alloc(b64data_size);
	unsigned int hmacsize;
	char *hmac = NULL;
	b64_encode(header, strlen(header), b64header, b64header_size);
	b64_encode(payload, strlen(payload), b64payload, b64payload_size);
	b64url(b64header);
	b64url(b64payload);
	snprintf(b64data, b64data_size, "%s.%s", b64header, b64payload); // generate first part of the token
	if(cfg.method != METHOD_NONE){
		hmac = safe_alloc(EVP_MAX_MD_SIZE);
		hmac_hash(cfg.method, cfg.secret, strlen(cfg.secret), b64data, strlen(b64data), hmac, &hmacsize); // calculate the signature hash
		b64_encode(hmac, hmacsize, b64sig, b64sig_size);
		b64url(b64sig);
		strlcat(b64data, ".", b64data_size); // append signature hash to token
		strlcat(b64data, b64sig, b64data_size);
	}
	safe_free(b64header);
	safe_free(b64payload);
	if(cfg.method != METHOD_NONE){
		safe_free(b64sig);
		safe_free(hmac);
	}

	return b64data;
}


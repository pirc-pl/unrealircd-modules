/*
 * Module skeleton, by Carsten V. Munk 2001 <stskeeps@tspre.org>
 */
 
 /* for compile, use:
 EXLIBS="-lmysqlclient" make
 */

#define USE_MYSQL
// change #define to #undef to disable mysql support

#ifdef USE_MYSQL
#define MYCONF "wwwstats"
#define DEFAULT_MYSQL_INTERVAL 900
#define list_add list_add_MYSQL
#include <mysql/mysql.h>
#undef list_add
#endif
#include "unrealircd.h"
#include "threads.h"
#include <sys/socket.h>
#include <sys/un.h>

struct chanStats_s {
	aChannel *chan;
	char chname[2*CHANNELLEN+1];
	int msg;
	int exists;
	struct chanStats_s *next;
};

struct channelInfo_s {
	int hashnum;
	aChannel *chan;
	int messages;
};

struct asendInfo_s {
	int sock;
	char *buf;
	int bufsize;
	char *tmpbuf;
};

typedef struct chanStats_s chanStats;
typedef struct channelInfo_s channelInfo;
typedef struct asendInfo_s asendInfo;

int counter;
time_t init_time;

int stats_socket;
THREAD thr;
MUTEX chans_mutex;
int chans_mutex_ai;
char send_buf[4096];
struct sockaddr_un stats_addr;
#ifdef USE_MYSQL
THREAD mysql_thr;
MYSQL *stats_db;
#endif

char* wwwstats_msg(aClient *sptr, aChannel *chptr, char *msg, int notice);
void wwwstats_thr(void*);
void asend_sprintf(asendInfo *info, char *fmt, ...);
void append_int_param(asendInfo *info, char *param, int value);
int getChannelInfo(channelInfo *prev);
aChannel *getChanByName(char *name);
void removeExpiredChannels();
char *tmp_escape(char *d, const char *a);
char *json_escape(char *d, const char *a);
void appendChannel(aChannel *ch, int messages);
#ifdef USE_MYSQL
void saveChannels(time_t act_time);
void saveStats(time_t act_time);
int mysql_query_sprintf(char *buf, char *fmt, ...);
void wwwstats_mysql_thr(void *d);
void loadChannels(void);
void send_mysql_error(void);
#endif
int wwwstats_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
int wwwstats_configposttest(int *errs);
int wwwstats_configrun(ConfigFile *cf, ConfigEntry *ce, int type);

chanStats *chans, *chans_last;

// config file stuff, based on Gottem's module

#ifdef USE_MYSQL
static char *mysql_user;
static char *mysql_pass;
static char *mysql_db;
static char *mysql_host;
static int use_mysql;
static int mysql_interval;
#endif
static char *socket_path;
int socket_hpath=0;

int wwwstats_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs) {
	ConfigEntry *cep; // For looping through our bl0cc
	int errors = 0; // Error count
	int i; // iter8or m8
	
#ifdef USE_MYSQL
	int mysql_huser=0, mysql_hpass=0, mysql_hdb=0, mysql_en=0, mysql_hhost=0;
#endif

	// Since we'll add a new top-level block to unrealircd.conf, need to filter on CONFIG_MAIN lmao
	if(type != CONFIG_MAIN)
		return 0; // Returning 0 means idgaf bout dis

	// Check for valid config entries first
	if(!ce || !ce->ce_varname)
		return 0;

	// If it isn't our bl0ck, idc
	if(strcmp(ce->ce_varname, MYCONF))
		return 0;

	// Loop dat shyte fam
	for(cep = ce->ce_entries; cep; cep = cep->ce_next) {
		// Do we even have a valid name l0l?
		if(!cep->ce_varname) {
			config_error("%s:%i: blank %s item", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF); // Rep0t error
			errors++; // Increment err0r count fam
			continue; // Next iteration imo tbh
		}

#ifdef USE_MYSQL
		if(!strcmp(cep->ce_varname, "mysql-user")) {
			if(!cep->ce_vardata) {
				config_error("%s:%i: %s::%s must be a string", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
				errors++; // Increment err0r count fam
				continue;
			}
			mysql_huser=1;
			continue;
		}

		if(!strcmp(cep->ce_varname, "mysql-pass")) {
			if(!cep->ce_vardata) {
				config_error("%s:%i: %s::%s must be a string", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
				errors++; // Increment err0r count fam
				continue;
			}
			mysql_hpass=1;
			continue;
		}
		
		if(!strcmp(cep->ce_varname, "mysql-db")) {
			if(!cep->ce_vardata) {
				config_error("%s:%i: %s::%s must be a string", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
				errors++; // Increment err0r count fam
				continue;
			}
			mysql_hdb=1;
			continue;
		}
		
		if(!strcmp(cep->ce_varname, "mysql-host")) {
			if(!cep->ce_vardata) {
				config_error("%s:%i: %s::%s must be a string", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
				errors++; // Increment err0r count fam
				continue;
			}
			mysql_hhost=1;
			continue;
		}
		
		if(!strcmp(cep->ce_varname, "mysql-interval")) {
			if(!cep->ce_vardata) {
				config_error("%s:%i: %s::%s must be an integer between 1 and 1000 (minutes)", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
				errors++; // Increment err0r count fam
				continue; // Next iteration imo tbh
			}
			// Should be an integer yo
			for(i = 0; cep->ce_vardata[i]; i++) {
				if(!isdigit(cep->ce_vardata[i])) {
					config_error("%s:%i: %s::%s must be an integer between 1 and 1000 (minutes)", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
					errors++; // Increment err0r count fam
					break;
				}
			}
			if(!errors && (atoi(cep->ce_vardata) < 1 || atoi(cep->ce_vardata) > 1000)) {
				config_error("%s:%i: %s::%s must be an integer between 1 and 1000 (minutes)", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
				errors++; // Increment err0r count fam
			}
			continue;
		}

		if(!strcmp(cep->ce_varname, "use-mysql")) { // no value expected
			mysql_en = 1;
			continue;
		}
#endif

		if(!strcmp(cep->ce_varname, "socket-path")) {
			if(!cep->ce_vardata) {
				config_error("%s:%i: %s::%s must be a path", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname);
				errors++; // Increment err0r count fam
				continue;
			}
			socket_hpath = 1;
			continue;
		}

		// Anything else is unknown to us =]
		config_warn("%s:%i: unknown item %s::%s", cep->ce_fileptr->cf_filename, cep->ce_varlinenum, MYCONF, cep->ce_varname); // So display just a warning
	}
	
	if(mysql_en && (!mysql_huser || !mysql_hpass || !mysql_hdb || !mysql_hhost)){
		config_warn("m_wwwstats: error: your mysql configuration is incomplete! Please either correct or disable it!");
		errors++;
	}
	
	*errs = errors;
	return errors ? -1 : 1; // Returning 1 means "all good", -1 means we shat our panties
}

int wwwstats_configposttest(int *errs) {
	if(!socket_hpath){
		config_warn("m_wwwstats: warning: socket path not specified! Socket won't be created.");
	}
	return 1;
}

// "Run" the config (everything should be valid at this point)
int wwwstats_configrun(ConfigFile *cf, ConfigEntry *ce, int type) {
	ConfigEntry *cep; // For looping through our bl0cc

	// Since we'll add a new top-level block to unrealircd.conf, need to filter on CONFIG_MAIN lmao
	if(type != CONFIG_MAIN)
		return 0; // Returning 0 means idgaf bout dis

	// Check for valid config entries first
	if(!ce || !ce->ce_varname)
		return 0;

	// If it isn't our bl0cc, idc
	if(strcmp(ce->ce_varname, MYCONF))
		return 0;

	// Loop dat shyte fam
	for(cep = ce->ce_entries; cep; cep = cep->ce_next) {
		// Do we even have a valid name l0l?
		if(!cep->ce_varname)
			continue; // Next iteration imo tbh

#ifdef USE_MYSQL
		if(cep->ce_vardata && !strcmp(cep->ce_varname, "mysql-user")) {
			mysql_user = strdup(cep->ce_vardata);
			continue;
		}
		
		if(cep->ce_vardata && !strcmp(cep->ce_varname, "mysql-pass")) {
			mysql_pass = strdup(cep->ce_vardata);
			continue;
		}
		
		if(cep->ce_vardata && !strcmp(cep->ce_varname, "mysql-db")) {
			mysql_db = strdup(cep->ce_vardata);
			continue;
		}

		if(cep->ce_vardata && !strcmp(cep->ce_varname, "mysql-host")) {
			mysql_host = strdup(cep->ce_vardata);
			continue;
		}
		
		if(!strcmp(cep->ce_varname, "mysql-interval")) {
			mysql_interval = atoi(cep->ce_vardata);
			continue;
		}
		
		if(!strcmp(cep->ce_varname, "use-mysql")) {
			use_mysql = 1;
			continue;
		}
#endif
		
		if(cep->ce_vardata && !strcmp(cep->ce_varname, "socket-path")) {
			socket_path = strdup(cep->ce_vardata);
			continue;
		}
	}
#ifdef USE_MYSQL
	if(mysql_interval == 0) mysql_interval = DEFAULT_MYSQL_INTERVAL;
#endif
	return 1; // We good
}

ModuleHeader MOD_HEADER(m_wwwstats)
  = {
	"m_wwwstats",     /* Name of module */
	"$Id: v1.07 2018/12/28 rocket/k4be$", /* Version */
	"Provides data for network stats", /* Short description of module */
	"3.2-b8-1",
	NULL 
    };

// Configuration testing-related hewks go in testing phase obv
MOD_TEST(m_wwwstats) {
	// We have our own config block so we need to checkem config obv m9
	// Priorities don't really matter here
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, wwwstats_configtest);
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGPOSTTEST, 0, wwwstats_configposttest);
	return MOD_SUCCESS;
}

/* This is called on module init, before Server Ready */
MOD_INIT(m_wwwstats)
{
	/*
	 * We call our add_Command crap here
	*/
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, wwwstats_configrun);
	HookAddPChar(modinfo->handle, HOOKTYPE_PRE_CHANMSG, 0, wwwstats_msg);

	return MOD_SUCCESS;
}

/* Is first run when server is 100% ready */
MOD_LOAD(m_wwwstats)
{
	#ifdef USE_MYSQL
	MYSQL_RES *res;
	MYSQL_ROW row;
	#endif
	
	if(socket_path){
		stats_addr.sun_family = AF_UNIX;
		strcpy(stats_addr.sun_path, socket_path);
		unlink(stats_addr.sun_path);	// remove old socket if exists
	}

	#ifdef USE_MYSQL
	stats_db = mysql_init(NULL);
	if(!stats_db) send_mysql_error(); // init failed
	#endif
	IRCCreateMutex(chans_mutex);
	chans_mutex_ai = 0;
	counter = 0;

	chans = NULL;
	chans_last = NULL;

	if(socket_path){
		stats_socket = socket(PF_UNIX, SOCK_STREAM, 0);
		bind(stats_socket, (struct sockaddr*) &stats_addr, SUN_LEN(&stats_addr));
		chmod(socket_path, 0777);
		listen(stats_socket, 5); // open socket
	}

	#ifdef USE_MYSQL
	if(use_mysql && mysql_host && mysql_user && mysql_pass && mysql_db){ // initialize DB
		mysql_real_connect(stats_db, mysql_host, mysql_user, mysql_pass, mysql_db, 0, NULL, 0);

		mysql_query(stats_db, "CREATE TABLE IF NOT EXISTS `chanlist` (`id` int(11) NOT NULL AUTO_INCREMENT, `date` int(11), `name` char(64), `topic` text, `users` int(11),  `messages` int(11), PRIMARY KEY (`id`), UNIQUE KEY `name` (`name`,`users`,`messages`), KEY `name_3` (`name`), KEY `date` (`date`) )");
		mysql_query(stats_db, "CREATE TABLE IF NOT EXISTS `stat` (`id` int(11) NOT NULL AUTO_INCREMENT, `date` int(11), `clients` int(11), `servers` int(11), `messages` int(11), `channels` int(11), PRIMARY KEY (`id`), UNIQUE KEY `changes` (`clients`,`servers`,`messages`,`channels`), KEY `date` (`date`) )");

		mysql_query(stats_db, "SELECT messages FROM stat ORDER BY id DESC LIMIT 1"); // read old messages count to continue counting
		res = mysql_use_result(stats_db);
		if(!res) send_mysql_error(); else {
			if((row = mysql_fetch_row(res))) {
				counter = strtoul(row[0], NULL, 10);
			}
			mysql_free_result(res);
		}

		loadChannels();
	}

	#endif
	IRCCreateThread(thr, wwwstats_thr, NULL);
	#ifdef USE_MYSQL
	if(stats_db) IRCCreateThread(mysql_thr, wwwstats_mysql_thr, NULL);
	#endif

	return MOD_SUCCESS;
}

/* Called when module is unloaded */
MOD_UNLOAD(m_wwwstats)
{
	time_t act_time;
	chanStats *next;

	pthread_cancel(thr);
	pthread_join(thr, NULL);
	#ifdef USE_MYSQL
	if(stats_db){
		pthread_cancel(mysql_thr);
		pthread_join(mysql_thr, NULL);
	}
	#endif

	close(stats_socket);
	unlink(stats_addr.sun_path);

	act_time = time(NULL);

	#ifdef USE_MYSQL
	saveStats(act_time);
	saveChannels(act_time);
	#endif

//      for(;chans;chans=chans->next) free(chans);
	for(;chans;chans=next) {
		next=chans->next;
		free(chans);
	}
	#ifdef USE_MYSQL
	if(stats_db) mysql_close(stats_db); // free our strings
	if(mysql_user) free(mysql_user);
	if(mysql_pass) free(mysql_pass);
	if(mysql_db) free(mysql_db);
	if(mysql_host) free(mysql_host);
	#endif

	if(socket_path) free(socket_path);
	
	return MOD_SUCCESS;
}

char* wwwstats_msg(aClient *sptr, aChannel *chptr, char *msg, int notice) { // called on channel messages
	chanStats *lp;
	#ifdef USE_MYSQL
	char name[2*CHANNELLEN+1];
	char buf[2048];
	MYSQL_RES *res;
	MYSQL_ROW row;
	#endif
	int c_msg;
	counter++;
	for(lp=chans; lp; lp=lp->next) if(lp->chan==chptr) break;

	if(lp) lp->msg++; // if channel found, increase msg count
	else { // create new channel
		c_msg = 1;
		#ifdef USE_MYSQL
		if(use_mysql){
			tmp_escape(name, chptr->chname);
			mysql_query_sprintf(buf, "SELECT MAX(messages) FROM chanlist WHERE name=\"%s\" GROUP BY name", name);
			res = mysql_use_result(stats_db);
			if(!res) send_mysql_error(); else {
				if((row = mysql_fetch_row(res)))
					if(row[0]) c_msg = strtoul(row[0], NULL, 10);
				mysql_free_result(res);
			}
		}
		#endif
//	    sendto_realops("wwwstats: added channel %s, %d msgs", name, c_msg);
		appendChannel(chptr, c_msg);
	}
	return msg;
}

void wwwstats_thr(void *d) {
	char buf[2000];
	char topic[6*TOPICLEN+1];
	char name[6*CHANNELLEN+1];
	int i;
	int sock;
	channelInfo chinfo;
	asendInfo asinfo;
	struct sockaddr_un cli_addr;

	socklen_t slen = sizeof(cli_addr);

	asinfo.buf = send_buf;
	asinfo.bufsize = sizeof(send_buf);
	asinfo.tmpbuf = buf;

	aClient *acptr;

	while(1) {
		sock = accept(stats_socket, (struct sockaddr*) &cli_addr, &slen); // wait for a connection
		if(sock<0) break;
		asinfo.sock = sock;
		send_buf[0] = 0;
		asend_sprintf(&asinfo, "{"); // generate JSON data
		append_int_param(&asinfo, "clients", IRCstats.clients);
		append_int_param(&asinfo, "channels", IRCstats.channels);
		append_int_param(&asinfo, "operators", IRCstats.operators);
		append_int_param(&asinfo, "servers", IRCstats.servers);
		append_int_param(&asinfo, "messages", counter);

		i=0;

		asend_sprintf(&asinfo, "\"serv\":[");
		list_for_each_entry(acptr, &global_server_list, client_node){
			if (IsULine(acptr) && HIDE_ULINES)
				continue;
/*			asend_sprintf(&asinfo, "$stats['serv'][%d]['name'] = '%s';\n", i, acptr->name); // old code for PHP data
			asend_sprintf(&asinfo, "$stats['serv'][%d]['users'] = %ld;\n", i, acptr->serv->users);*/
			asend_sprintf(&asinfo, "%s{\"name\":\"%s\",\"users\":%1d}", i?",":"", acptr->name, acptr->serv->users);
			i++;
		}
		
		asend_sprintf(&asinfo, "],\"chan\":[");

		IRCMutexLock(chans_mutex);
		if(!chans_mutex_ai) removeExpiredChannels();
		chans_mutex_ai++;
		IRCMutexUnlock(chans_mutex);
		chinfo.chan = NULL;

		i=0;
		while(getChannelInfo(&chinfo)) {
			if(!PubChannel(chinfo.chan)) continue;
			asend_sprintf(&asinfo, "%s{\"name\":\"%s\",\"users\":%d,\"messages\":%d", i?",":"",
				json_escape(name, chinfo.chan->chname), chinfo.chan->users, chinfo.messages);
			if(chinfo.chan->topic)
				asend_sprintf(&asinfo, ",\"topic\":\"%s\"", json_escape(topic, chinfo.chan->topic));
			asend_sprintf(&asinfo, "}");
/*			asend_sprintf(&asinfo, "$stats['chan'][%d]['name'] = '%s';\n", i, tmp_escape(name, chinfo.chan->chname));
			asend_sprintf(&asinfo, "$stats['chan'][%d]['users'] = %d;\n", i, chinfo.chan->users);
			asend_sprintf(&asinfo, "$stats['chan'][%d]['messages'] = %d;\n", i, chinfo.messages);
			if(chinfo.chan->topic) asend_sprintf(&asinfo, "$stats['chan'][%d]['topic'] = '%s';\n", i, tmp_escape(topic, chinfo.chan->topic));*/
			
			i++;
		}
		
		asend_sprintf(&asinfo, "]}");

		IRCMutexLock(chans_mutex);
		chans_mutex_ai--;
		IRCMutexUnlock(chans_mutex);

		if(send_buf[0]) {
			send(sock, send_buf, strlen(send_buf), 0);
			send_buf[0] = 0;
		}

		close(sock);
	}
}

#ifdef USE_MYSQL

void wwwstats_mysql_thr(void *d) {
	time_t prev_time;
	time_t act_time;
	prev_time = 0;

	while(1) {
		act_time = time(NULL);
		if((act_time-prev_time)>=mysql_interval) { // continue if the interval has passed
			saveStats(act_time);

			IRCMutexLock(chans_mutex);
			if(!chans_mutex_ai) removeExpiredChannels();
			chans_mutex_ai++;
			IRCMutexUnlock(chans_mutex);

			saveChannels(act_time);

			IRCMutexLock(chans_mutex);
			chans_mutex_ai--;
			IRCMutexUnlock(chans_mutex);

			prev_time = act_time;
		}
		sleep(10);
	}
}

void saveChannels(time_t act_time) { // store all channel data to DB
	char buf[6*(TOPICLEN+CHANNELLEN)+256];
	char name[6*CHANNELLEN+1];
	char topic[6*TOPICLEN+1];
	channelInfo chinfo;
	
	if(!use_mysql) return;

	chinfo.chan = NULL;
	while(getChannelInfo(&chinfo)) {
		json_escape(name, chinfo.chan->chname);
		if(chinfo.chan->topic) json_escape(topic, chinfo.chan->topic);
		else topic[0] = 0;
		mysql_query_sprintf(buf, "INSERT IGNORE INTO chanlist VALUES (NULL, %d, \"%s\", \"%s\", %d, %d)", act_time, name, topic, chinfo.chan->users, chinfo.messages);
	}
}

void loadChannels(void){ // channel will be added automatically when a message comes
	char buf[2*CHANNELLEN+20];
	char name[2*CHANNELLEN+1];
	aChannel *ch;
	MYSQL_RES *res;
	MYSQL_ROW row;
	
	channelInfo chinfo;
	unsigned long cnt;
	
	if(!use_mysql) return;
	
	chinfo.chan = NULL;
	while(getChannelInfo(&chinfo)) {
		ch = chinfo.chan;
		tmp_escape(name, chinfo.chan->chname);
		mysql_query_sprintf(buf, "SELECT MAX(messages) FROM chanlist WHERE name = \"%s\"", name);
		res = mysql_use_result(stats_db);
		if(res && (row = mysql_fetch_row(res))){
			cnt = 0;
			if(row[0]) cnt = strtoul(row[0], NULL, 10);
			if(cnt > 0){
				appendChannel(ch, cnt);
//				sendto_realops("wwwstats: added from db: %s, %lu msgs", ch->chname, cnt);
			}
			mysql_free_result(res);
		}
	}
}

void saveStats(time_t act_time) { // store non-channel stats
	char buf[512];
	
	if(!use_mysql) return;
	
	mysql_query_sprintf(buf, "INSERT IGNORE INTO stat VALUES (NULL, %d, %d, %d, %d, %d)", act_time, IRCstats.clients, IRCstats.servers, counter, IRCstats.channels);
}

void send_mysql_error(void){
	sendto_realops("wwwstats: mysql error: %s",mysql_error(stats_db));
}
#endif


void appendChannel(aChannel *ch, int messages) {
	chanStats *lp;

	lp = malloc(sizeof(chanStats));
	lp->chan = ch;
	lp->msg = messages;
	strcpy(lp->chname, ch->chname);
	lp->next = NULL;
	if(chans_last) chans_last->next = lp;
	chans_last = lp;
	if(!chans) chans = lp;
}

void removeExpiredChannels() {
	int hashnum;
	aChannel *c;
	chanStats *lp, *lpprev, *lpnext;
	
	for(lp=chans; lp; lp=lp->next) lp->exists = 0;

	for(hashnum=0; hashnum<CH_MAX; hashnum++) {
		c = (aChannel*) hash_get_chan_bucket(hashnum);
		while(c) {
			for(lp=chans; lp; lp=lp->next) if(lp->chan==c) break;
			if(lp) lp->exists = 1;
			c = c->hnextch;
		}
	}

	lpprev = NULL;
	lpnext = NULL;
	for(lp=chans; lp; lp=lpnext) {
		if(!lp->exists) {
//			sendto_realops("wwwstats: deleted channel %s", lp->chname);
			if(lpprev) lpprev->next = lp->next;
				else chans = lp->next;
			if(!lp->next) chans_last = lpprev;
			lpnext = lp->next;
			free(lp);
			continue;
		}
		lpnext = lp->next;
		lpprev = lp;
	}
}

aChannel *getChanByName(char *name) {
	channelInfo chinfo;

	chinfo.chan = NULL;
	while(getChannelInfo(&chinfo)) { 
		if(strcmp(chinfo.chan->chname, name)==0) return chinfo.chan;
	}
	return NULL;
}

int getChannelInfo(channelInfo *prev) {
	int hashnum = 0;
	int messages = 0;
	aChannel *c = NULL;
	chanStats *lp;

	if(prev->chan) {
		hashnum = prev->hashnum;
		c = prev->chan->hnextch;
		if(!c) hashnum++;
	}

	if(!c) for(; hashnum<CH_MAX; hashnum++) {
		c = (aChannel*) hash_get_chan_bucket(hashnum);
		if(c) break;
	}
	if(!c) return 0;

	for(lp=chans; lp; lp=lp->next) if(lp->chan==c) break;
	if(lp) messages = lp->msg;

	prev->hashnum = hashnum;
	prev->chan = c;
	prev->messages = messages;
	return 1;
}

#ifdef USE_MYSQL
int mysql_query_sprintf(char *buf, char *fmt, ...) {
	int ret;
	va_list list;
	va_start(list, fmt);
	vsprintf(buf, fmt, list);
	va_end(list);
	ret = mysql_query(stats_db, buf);
	if(ret){
	      sendto_realops("wwwstats: mysql query error: %s",mysql_error(stats_db));
	}
	return ret;
}
#endif

void asend_sprintf(asendInfo *info, char *fmt, ...) {
	int bl, tl;
	va_list list;
	va_start(list, fmt);
	vsprintf(info->tmpbuf, fmt, list);
	bl = strlen(info->tmpbuf);
	tl = strlen(info->buf);
	if((bl+tl)>=info->bufsize) {
		send(info->sock, info->buf, tl, 0);
		info->buf[0] = 0;
	}

	strcat(info->buf, info->tmpbuf);
	va_end(list);
}

void append_int_param(asendInfo *info, char *param, int value) {
//	asend_sprintf(info, "$stats['%s'] = %d;\n", param, value);
	asend_sprintf(info, "\"%s\":%d,", param, value);
}

char *tmp_escape(char *d, const char *a) { // now only for sql queries
	int diff=0;
	int i;
	for(i=0; a[i]; i++) {
		if((a[i]=='"') || (a[i]=='\\')) {
			d[diff+i] = '\\';
			diff++;
		}
		d[diff+i] = a[i];
	}
	d[diff+i] = 0;
	return d;
}

char *json_escape(char *d, const char *a) {
	int diff=0;
	int i, j;
	char buf[7];
    for(i=0; a[i]; i++) {
        if(a[i] == '"' || a[i] == '\\' || ('\x00' <= a[i] && a[i] <= '\x1f')) { // unicode chars don't need to be escaped
        	sprintf(buf, "\\u%04x", (int)a[i]);
        	for(j=0; j<6; j++){
	        	d[diff+i] = buf[j];
	        	diff++;
	        }
	        diff--;
        } else {
            d[diff+i] = a[i];
        }
    }
	d[diff+i] = 0;
	return d;
}


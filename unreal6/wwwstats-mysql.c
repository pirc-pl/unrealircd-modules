 /* for compile, use:
 EXLIBS="-lmysqlclient" make
 If you accidentaly compiled without it and the module fails to load, remove the old result with `rm src/modules/third/wwwstats-mysql.so` and then recompile
 */

#define USE_MYSQL

/* Copyright (C) All Rights Reserved
** Written by rocket & k4be
** Website: https://github.com/pirc-pl/unrealircd-modules/
** License: GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
*/

/*** <<<MODULE MANAGER START>>>
module
{
        documentation "https://github.com/pirc-pl/unrealircd-modules/blob/master/README.md#wwwstats-mysql";
        troubleshooting "In case of problems, contact k4be on irc.pirc.pl.";
        min-unrealircd-version "6.*";
        post-install-text {
                "The module is installed. Now you need to add a loadmodule line:";
                "loadmodule \"third/wwwstats\";";
                "and create a valid configuration block as in the example below:";
                "wwwstats {";
				" socket-path \"/tmp/wwwstats.sock\"; // do not specify if you don't want the socket";
				" use-mysql; // remove this line if you don't want mysql";
				" mysql-interval \"900\"; // time in seconds, default is 900";
				" mysql-host \"localhost\";";
				" mysql-db \"database\";";
				" mysql-user \"username\";";
				" mysql-pass \"password\";";
				"};";
				"And /REHASH the IRCd.";
				"";
				"The module must be build with the command:";
				"EXLIBS=\"-lmysqlclient\" make install";
				"Detailed documentation is available on https://github.com/pirc-pl/unrealircd-modules/blob/master/README.md#wwwstats-mysql";
        }
}
*** <<<MODULE MANAGER END>>>
*/

#define MYCONF "wwwstats"

#ifdef USE_MYSQL
#define DEFAULT_MYSQL_INTERVAL 900
#define list_add list_add_MYSQL
#include <mysql/mysql.h>
#undef list_add
#endif

#include "unrealircd.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#ifndef TOPICLEN
#define TOPICLEN MAXTOPICLEN
#endif

#if (UNREAL_VERSION_GENERATION == 5 && UNREAL_VERSION_MAJOR == 0 && UNREAL_VERSION_MINOR < 5)
#define MESSAGE_SENDTYPE int
#else
#define MESSAGE_SENDTYPE SendType
#endif

#define CHANNEL_MESSAGE_COUNT(channel) moddata_channel(channel, message_count_md).i

int counter;
time_t init_time;

int stats_socket;
struct sockaddr_un stats_addr;
ModDataInfo *message_count_md;
#ifdef USE_MYSQL
MYSQL *stats_db;
#endif

#if UNREAL_VERSION_TIME<202340
int wwwstats_msg(Client *sptr, Channel *chptr, MessageTag *mtags, const char *msg, MESSAGE_SENDTYPE sendtype);
#else
int wwwstats_msg(Client *sptr, Channel *chptr, MessageTag **mtags, const char *msg, MESSAGE_SENDTYPE sendtype);
#endif
EVENT(wwwstats_socket_evt);
char *tmp_escape(char *d, const char *a);

#ifdef USE_MYSQL
void saveChannels(time_t act_time);
void saveStats(time_t act_time);
int mysql_query_sprintf(char *buf, char *fmt, ...);
void loadChannels(void);
void send_mysql_error(void);
EVENT(wwwstats_mysql_evt);
int wwwstats_channel_create(Channel *channel);
void wwwstats_mysql_connect(void);
#endif

void md_free(ModData *md);
int wwwstats_configtest(ConfigFile *cf, ConfigEntry *ce, int type, int *errs);
int wwwstats_configposttest(int *errs);
int wwwstats_configrun(ConfigFile *cf, ConfigEntry *ce, int type);

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
	if(!ce || !ce->name)
		return 0;

	// If it isn't our bl0ck, idc
	if(strcmp(ce->name, MYCONF))
		return 0;

	// Loop dat shyte fam
	for(cep = ce->items; cep; cep = cep->next) {
		// Do we even have a valid name l0l?
		if(!cep->name) {
			config_error("%s:%i: blank %s item", cep->file->filename, cep->line_number, MYCONF); // Rep0t error
			errors++; // Increment err0r count fam
			continue; // Next iteration imo tbh
		}

#ifdef USE_MYSQL
		if(!strcmp(cep->name, "mysql-user")) {
			if(!cep->value) {
				config_error("%s:%i: %s::%s must be a string", cep->file->filename, cep->line_number, MYCONF, cep->name);
				errors++; // Increment err0r count fam
				continue;
			}
			mysql_huser=1;
			continue;
		}

		if(!strcmp(cep->name, "mysql-pass")) {
			if(!cep->value) {
				config_error("%s:%i: %s::%s must be a string", cep->file->filename, cep->line_number, MYCONF, cep->name);
				errors++; // Increment err0r count fam
				continue;
			}
			mysql_hpass=1;
			continue;
		}
		
		if(!strcmp(cep->name, "mysql-db")) {
			if(!cep->value) {
				config_error("%s:%i: %s::%s must be a string", cep->file->filename, cep->line_number, MYCONF, cep->name);
				errors++; // Increment err0r count fam
				continue;
			}
			mysql_hdb=1;
			continue;
		}
		
		if(!strcmp(cep->name, "mysql-host")) {
			if(!cep->value) {
				config_error("%s:%i: %s::%s must be a string", cep->file->filename, cep->line_number, MYCONF, cep->name);
				errors++; // Increment err0r count fam
				continue;
			}
			mysql_hhost=1;
			continue;
		}
		
		if(!strcmp(cep->name, "mysql-interval")) {
			if(!cep->value) {
				config_error("%s:%i: %s::%s must be an integer between 1 and 1000 (minutes)", cep->file->filename, cep->line_number, MYCONF, cep->name);
				errors++; // Increment err0r count fam
				continue; // Next iteration imo tbh
			}
			// Should be an integer yo
			for(i = 0; cep->value[i]; i++) {
				if(!isdigit(cep->value[i])) {
					config_error("%s:%i: %s::%s must be an integer between 1 and 1000 (minutes)", cep->file->filename, cep->line_number, MYCONF, cep->name);
					errors++; // Increment err0r count fam
					break;
				}
			}
			if(!errors && (atoi(cep->value) < 1 || atoi(cep->value) > 1000)) {
				config_error("%s:%i: %s::%s must be an integer between 1 and 1000 (minutes)", cep->file->filename, cep->line_number, MYCONF, cep->name);
				errors++; // Increment err0r count fam
			}
			continue;
		}

		if(!strcmp(cep->name, "use-mysql")) { // no value expected
			mysql_en = 1;
			continue;
		}
#endif

		if(!strcmp(cep->name, "socket-path")) {
			if(!cep->value) {
				config_error("%s:%i: %s::%s must be a path", cep->file->filename, cep->line_number, MYCONF, cep->name);
				errors++; // Increment err0r count fam
				continue;
			}
			socket_hpath = 1;
			continue;
		}

		// Anything else is unknown to us =]
		config_warn("%s:%i: unknown item %s::%s", cep->file->filename, cep->line_number, MYCONF, cep->name); // So display just a warning
	}

#ifdef USE_MYSQL
	if(mysql_en && (!mysql_huser || !mysql_hpass || !mysql_hdb || !mysql_hhost)){
		config_warn("m_wwwstats: error: your mysql configuration is incomplete! Please either correct or disable it!");
		errors++;
	}
#endif
	
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
	if(!ce || !ce->name)
		return 0;

	// If it isn't our bl0cc, idc
	if(strcmp(ce->name, MYCONF))
		return 0;

	// Loop dat shyte fam
	for(cep = ce->items; cep; cep = cep->next) {
		// Do we even have a valid name l0l?
		if(!cep->name)
			continue; // Next iteration imo tbh

#ifdef USE_MYSQL
		if(cep->value && !strcmp(cep->name, "mysql-user")) {
			mysql_user = strdup(cep->value);
			continue;
		}
		
		if(cep->value && !strcmp(cep->name, "mysql-pass")) {
			mysql_pass = strdup(cep->value);
			continue;
		}
		
		if(cep->value && !strcmp(cep->name, "mysql-db")) {
			mysql_db = strdup(cep->value);
			continue;
		}

		if(cep->value && !strcmp(cep->name, "mysql-host")) {
			mysql_host = strdup(cep->value);
			continue;
		}
		
		if(!strcmp(cep->name, "mysql-interval")) {
			mysql_interval = atoi(cep->value);
			continue;
		}
		
		if(!strcmp(cep->name, "use-mysql")) {
			use_mysql = 1;
			continue;
		}
#endif
		
		if(cep->value && !strcmp(cep->name, "socket-path")) {
			socket_path = strdup(cep->value);
			continue;
		}
	}
#ifdef USE_MYSQL
	if(mysql_interval == 0) mysql_interval = DEFAULT_MYSQL_INTERVAL;
#endif
	return 1; // We good
}

ModuleHeader MOD_HEADER = {
	"third/wwwstats-mysql",   /* Name of module */
	"6.0", /* Version */
	"Provides data for network stats", /* Short description of module */
	"rocket, k4be",
	"unrealircd-6"
};

// Configuration testing-related hewks go in testing phase obv
MOD_TEST(){
	// We have our own config block so we need to checkem config obv m9
	// Priorities don't really matter here
	socket_hpath = 0;

	HookAdd(modinfo->handle, HOOKTYPE_CONFIGTEST, 0, wwwstats_configtest);
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGPOSTTEST, 0, wwwstats_configposttest);
	return MOD_SUCCESS;
}

/* This is called on module init, before Server Ready */
MOD_INIT(){
	ModDataInfo mreq;
	/*
	 * We call our add_Command crap here
	*/
	HookAdd(modinfo->handle, HOOKTYPE_CONFIGRUN, 0, wwwstats_configrun);
	HookAdd(modinfo->handle, HOOKTYPE_PRE_CHANMSG, 0, wwwstats_msg);
	#ifdef USE_MYSQL
	HookAdd(modinfo->handle, HOOKTYPE_CHANNEL_CREATE, 0, wwwstats_channel_create);
	#endif

	memset(&mreq, 0 , sizeof(mreq));
	mreq.type = MODDATATYPE_CHANNEL;
	mreq.name = "message_count",
	mreq.free = md_free;
	message_count_md = ModDataAdd(modinfo->handle, mreq);
	if(!message_count_md){
		config_error("[%s] Failed to request message_count moddata: %s", MOD_HEADER.name, ModuleGetErrorStr(modinfo->handle));
		return MOD_FAILED;
	}

	return MOD_SUCCESS;
}

/* Is first run when server is 100% ready */
MOD_LOAD(){
	if(socket_path){
		stats_addr.sun_family = AF_UNIX;
		strcpy(stats_addr.sun_path, socket_path);
		unlink(stats_addr.sun_path);	// remove old socket if exists
	}
	
	counter = 0;

	if(socket_path){
		stats_socket = socket(PF_UNIX, SOCK_STREAM, 0);
		bind(stats_socket, (struct sockaddr*) &stats_addr, SUN_LEN(&stats_addr));
		chmod(socket_path, 0777);
		listen(stats_socket, 5); // open socket
		fcntl(stats_socket, F_SETFL, O_NONBLOCK);
	}

	#ifdef USE_MYSQL
	wwwstats_mysql_connect();
	#endif
	EventAdd(modinfo->handle, "wwwstats_socket", wwwstats_socket_evt, NULL, 100, 0);
	#ifdef USE_MYSQL
	EventAdd(modinfo->handle, "wwwstats_mysql", wwwstats_mysql_evt, NULL, mysql_interval*1000, 0);
	#endif

	return MOD_SUCCESS;
}

#ifdef USE_MYSQL
void wwwstats_mysql_connect(void){
	MYSQL_RES *res;
	MYSQL_ROW row;
	if(stats_db) mysql_close(stats_db);
	stats_db = mysql_init(NULL);
	if(!stats_db) send_mysql_error(); // init failed
	if(stats_db && use_mysql && mysql_host && mysql_user && mysql_pass && mysql_db){ // initialize DB
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
}
#endif

/* Called when module is unloaded */
MOD_UNLOAD(){
	time_t act_time;

	close(stats_socket);
	unlink(stats_addr.sun_path);

	act_time = time(NULL);

	#ifdef USE_MYSQL
	saveStats(act_time);
	saveChannels(act_time);
	if(stats_db) mysql_close(stats_db); // free our strings
	if(mysql_user) free(mysql_user);
	if(mysql_pass) free(mysql_pass);
	if(mysql_db) free(mysql_db);
	if(mysql_host) free(mysql_host);
	#endif

	if(socket_path) free(socket_path);
	
	return MOD_SUCCESS;
}

void md_free(ModData *md){
	md->i = 0;
}

#if UNREAL_VERSION_TIME<202340
int wwwstats_msg(Client *sptr, Channel *chptr, MessageTag *mtags, const char *msg, MESSAGE_SENDTYPE sendtype)
#else
int wwwstats_msg(Client *sptr, Channel *chptr, MessageTag **mtags, const char *msg, MESSAGE_SENDTYPE sendtype)
#endif
{ // called on channel messages
	counter++;
	CHANNEL_MESSAGE_COUNT(chptr)++;
	return HOOK_CONTINUE;
}


#ifdef USE_MYSQL
int wwwstats_channel_create(Channel *channel){ // load message count for newly created channels
	char name[2*CHANNELLEN+1];
	char buf[2048];
	MYSQL_RES *res;
	MYSQL_ROW row;

	if(!use_mysql) return HOOK_CONTINUE;

	tmp_escape(name, channel->name);
	mysql_query_sprintf(buf, "SELECT messages FROM chanlist WHERE name=\"%s\" ORDER BY messages DESC LIMIT 1", name);
	res = mysql_use_result(stats_db);
	if(!res) send_mysql_error(); else {
		if((row = mysql_fetch_row(res)))
			if(row[0]) CHANNEL_MESSAGE_COUNT(channel) = strtoul(row[0], NULL, 10);
		mysql_free_result(res);
	}
	return HOOK_CONTINUE;
}
#endif

EVENT(wwwstats_socket_evt){
	char topic[6*TOPICLEN+1];
	char name[6*CHANNELLEN+1];
	int sock;
	struct sockaddr_un cli_addr;
	socklen_t slen;
	Client *acptr;
	Channel *channel;
	unsigned int hashnum;
	json_t *output = NULL;
	json_t *servers = NULL;
	json_t *channels = NULL;
	json_t *server_j = NULL;
	json_t *channel_j = NULL;
	char *result;

	if(!socket_hpath) return; // nothing to do

	sock = accept(stats_socket, (struct sockaddr*) &cli_addr, &slen); // wait for a connection
	
	slen = sizeof(cli_addr);
	
	if(sock<0){
		if(errno == EWOULDBLOCK || errno == EAGAIN) return;
		unreal_log(ULOG_ERROR, "wwwstats", "WWWSTATS_ACCEPT_ERROR", NULL, "Socket accept error: $error", log_data_string("error", strerror(errno)));
		return;
	}
	
	output = json_object();
	servers = json_array();
	channels = json_array();

	json_object_set_new(output, "clients", json_integer(irccounts.clients));
	json_object_set_new(output, "channels", json_integer(irccounts.channels));
	json_object_set_new(output, "operators", json_integer(irccounts.operators));
	json_object_set_new(output, "servers", json_integer(irccounts.servers));
	json_object_set_new(output, "messages", json_integer(counter));

	list_for_each_entry(acptr, &global_server_list, client_node){
		if (IsULine(acptr) && HIDE_ULINES)
			continue;
		server_j = json_object();
		json_object_set_new(server_j, "name", json_string_unreal(acptr->name));
		json_object_set_new(server_j, "users", json_integer(acptr->server->users));
		json_array_append_new(servers, server_j);
	}
	json_object_set_new(output, "serv", servers);

	for(hashnum = 0; hashnum < CHAN_HASH_TABLE_SIZE; hashnum++){
		for(channel = hash_get_chan_bucket(hashnum); channel; channel = channel->hnextch){
			if(!PubChannel(channel)) continue;
			channel_j = json_object();
			json_object_set_new(channel_j, "name", json_string_unreal(channel->name));
			json_object_set_new(channel_j, "users", json_integer(channel->users));
			json_object_set_new(channel_j, "messages", json_integer(CHANNEL_MESSAGE_COUNT(channel)));
			if(channel->topic)
				json_object_set_new(channel_j, "topic", json_string_unreal(channel->topic));
			json_array_append_new(channels, channel_j);
		}
	}
	json_object_set_new(output, "chan", channels);
	result = json_dumps(output, JSON_COMPACT);
	
	send(sock, result, strlen(result), 0);
	json_decref(output);
	safe_free(result);
	close(sock);
}

#ifdef USE_MYSQL
EVENT(wwwstats_mysql_evt){
	time_t act_time;
	act_time = time(NULL);
	
	saveStats(act_time);
	saveChannels(act_time);
}

void saveChannels(time_t act_time) { // store all channel data to DB
	char buf[6*(TOPICLEN+CHANNELLEN)+256];
	char name[6*CHANNELLEN+1];
	char topic[6*TOPICLEN+1];
	Channel *channel;
	unsigned int hashnum;
	
	if(!use_mysql) return;

	for(hashnum = 0; hashnum < CHAN_HASH_TABLE_SIZE; hashnum++){
		for(channel = hash_get_chan_bucket(hashnum); channel; channel = channel->hnextch){
			if(!PubChannel(channel)) continue;
			tmp_escape(name, channel->name);
			if(channel->topic) tmp_escape(topic, channel->topic);
			else topic[0] = 0;
			mysql_query_sprintf(buf, "INSERT IGNORE INTO chanlist VALUES (NULL, %d, \"%s\", \"%s\", %d, %d)", act_time, name, topic, channel->users, CHANNEL_MESSAGE_COUNT(channel));
		}
	}
}

void loadChannels(void){ // channel will be added automatically when a message comes
	char buf[2*CHANNELLEN+100];
	char name[2*CHANNELLEN+1];
	Channel *channel;
	MYSQL_RES *res;
	MYSQL_ROW row;
	unsigned long cnt;
	unsigned int hashnum;
	
	if(!use_mysql) return;
	
	for(hashnum = 0; hashnum < CHAN_HASH_TABLE_SIZE; hashnum++){
		for(channel = hash_get_chan_bucket(hashnum); channel; channel = channel->hnextch){
			tmp_escape(name, channel->name);
			mysql_query_sprintf(buf, "SELECT messages FROM chanlist WHERE name = \"%s\" ORDER BY messages DESC LIMIT 1", name);
			res = mysql_use_result(stats_db);
			if(res && (row = mysql_fetch_row(res))){
				cnt = 0;
				if(row[0]) cnt = strtoul(row[0], NULL, 10);
				if(cnt > 0){
					CHANNEL_MESSAGE_COUNT(channel) = cnt;
	//				sendto_realops("wwwstats: added from db: %s, %lu msgs", ch->chname, cnt);
				}
				mysql_free_result(res);
			}
		}
	}
}

void saveStats(time_t act_time) { // store non-channel stats
	char buf[512];
	
	if(!use_mysql) return;
	
	mysql_query_sprintf(buf, "INSERT IGNORE INTO stat VALUES (NULL, %d, %d, %d, %d, %d)", act_time, irccounts.clients, irccounts.servers, counter, irccounts.channels);
}

void send_mysql_error(void){
	unreal_log(ULOG_ERROR, "wwwstats", "WWWSTATS_MYSQL_ERROR", NULL, "mysql error: $error", log_data_string("error", mysql_error(stats_db)));
}

int mysql_query_sprintf(char *buf, char *fmt, ...) {
	int ret;
	va_list list;
	va_start(list, fmt);
	vsprintf(buf, fmt, list);
	va_end(list);
	if(!stats_db) wwwstats_mysql_connect(); // attempt reconnection
	ret = mysql_query(stats_db, buf);
	if(ret){
		unreal_log(ULOG_ERROR, "wwwstats", "WWWSTATS_MYSQL_ERROR", NULL, "mysql query error: $error", log_data_string("error", mysql_error(stats_db)));
	}
	return ret;
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
#endif


#include "unrealircd.h"

static ModuleInfo *showwebircMI = NULL;

ModuleHeader MOD_HEADER(m_showwebirc) = {
	"m_showwebirc",
	"$Id: v0.03 2018/12/14 k4be$",
	"Add SWHOIS info for WEBIRC users",
	"3.2-b8-1",
	NULL
};

static int showwebirc_userconnect(aClient *cptr);

MOD_INIT(m_showwebirc) {
	showwebircMI = modinfo;
	if(!HookAdd(modinfo->handle, HOOKTYPE_LOCAL_CONNECT, 0, showwebirc_userconnect)) return MOD_FAILED;
	return MOD_SUCCESS;
}

MOD_LOAD(m_showwebirc) {
	aClient *acptr;
	list_for_each_entry(acptr, &client_list, client_node){
		if(!IsPerson(acptr) || !MyClient(acptr)) continue;
		showwebirc_userconnect(acptr); // add info for all users upon module loading
	}
	return MOD_SUCCESS;
}

MOD_UNLOAD(m_showwebirc) {
	aClient *acptr;
	list_for_each_entry(acptr, &client_list, client_node){
		if(!IsPerson(acptr) || !MyClient(acptr)) continue;
		swhois_delete(acptr, "webirc", "*", &me, NULL); // delete info when unloading 
	}
	return MOD_SUCCESS;
}

static int showwebirc_userconnect(aClient *cptr) {
	ModDataInfo *moddata;
	moddata = findmoddata_byname("webirc", MODDATATYPE_CLIENT);
	if(moddata == NULL) return HOOK_CONTINUE;
	if(moddata_client(cptr, moddata).l){
		swhois_add(cptr, "webirc", 0, "is connecting via WEBIRC", &me, NULL);
	}
	return HOOK_CONTINUE;
}


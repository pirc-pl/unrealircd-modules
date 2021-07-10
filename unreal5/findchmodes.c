/* Copyright (C) All Rights Reserved
** Written by k4be
** Website: https://github.com/pirc-pl/unrealircd-modules/
** License: GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
*/

/*** <<<MODULE MANAGER START>>>
module
{
        documentation "https://github.com/pirc-pl/unrealircd-modules/blob/master/README.md";
        troubleshooting "In case of problems, contact k4be on irc.pirc.pl.";
        min-unrealircd-version "5.*";
        post-install-text {
                "The module is installed. Now all you need to do is add a loadmodule line:";
                "loadmodule \"third/findchmodes\";";
  				"And /REHASH the IRCd.";
				"The module does not need any other configuration.";
        }
}
*** <<<MODULE MANAGER END>>>
*/

#include "unrealircd.h"

#define MSG_FINDCHMODES "FINDCHMODES"
#define USAGE() { sendnotice(client, "Usage: /%s +character", MSG_FINDCHMODES); }

#if (UNREAL_VERSION_MAJOR<2) || (UNREAL_VERSION_MAJOR==2 && UNREAL_VERSION_MINOR==0)
#define OLDAPI // channel_modes() prototype change
#endif

CMD_FUNC(cmd_findchmodes);

ModuleHeader MOD_HEADER = {
	"third/findchmodes",   /* Name of module */
	"5.1", /* Version */
	"Find channels by channel modes", /* Short description of module */
	"k4be@PIRC",
	"unrealircd-5"
};

MOD_INIT() {
	CommandAdd(modinfo->handle, MSG_FINDCHMODES, cmd_findchmodes, MAXPARA, CMD_USER);
	return MOD_SUCCESS;
}

MOD_LOAD() {
	return MOD_SUCCESS;
}

MOD_UNLOAD() {
	return MOD_SUCCESS;
}

CMD_FUNC(cmd_findchmodes) {
	if(!IsOper(client)){
		sendnumeric(client, ERR_NOPRIVILEGES);
		return;
	}
	if(parc < 2 || BadPtr(parv[1])){
		USAGE();
		return;
	}
	char *arg = parv[1];
	if(*arg == '+') arg++;
	if(strlen(arg) != 1 || !isalpha(*arg)){
		USAGE();
		return;
	}
	unsigned int  hashnum;
	Channel *channel;
	int count = 0;
	for (hashnum = 0; hashnum < CHAN_HASH_TABLE_SIZE; hashnum++){
		for (channel = hash_get_chan_bucket(hashnum); channel; channel = channel->hnextch){
			if (!ValidatePermissionsForPath("channel:see:list:secret",client,NULL,channel,NULL)) continue;
			*modebuf = *parabuf = '\0';
			modebuf[1] = '\0';
			// using "me" here to get args for all channels, never retrieve channel keys though
#ifdef OLDAPI
			channel_modes((*channel->mode.key)?client:(Client *)&me, modebuf, parabuf, sizeof(modebuf), sizeof(parabuf), channel);
#else
			channel_modes((*channel->mode.key)?client:(Client *)&me, modebuf, parabuf, sizeof(modebuf), sizeof(parabuf), channel, 0);
#endif
			if(strchr(modebuf, *arg)){
				sendnumeric(client, RPL_CHANNELMODEIS, channel->chname, modebuf, parabuf);
				if(IsMember(client, channel)){
					sendnotice(client, "[findchmodes +%c] Notice: You're on %s", *arg, channel->chname);
				}
				count++;
			}
		}
	}
	if(count == 0){
		sendnotice(client, "[findchmodes +%c] Notice: No channels found", *arg);
	}
}


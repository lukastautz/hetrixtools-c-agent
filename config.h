// (unofficial) HetrixTools C agent config

// In the agent token file the server key/id (a 32 character hexadecimal string) is saved
#define CONFIG_TOKEN_PATH "/etc/hetrixtools_agent_token"

#define CONFIG_API_PATH "/"
#define CONFIG_API_HOST "sm.hetrixtools.net" // if you change this you most likely will have to regenerate the TAs

// As the API v1 doesn't support to supply steal statistics, you can choose to transmit the steal instead of the IOwait, but it will still be shown as IOwait in the HetrixTools statistics
// #define CONFIG_SWITCH_IOWAIT_STEAL

#include "TA.h"
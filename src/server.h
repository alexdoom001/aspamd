/* 
 * aspamd - advanced spam daemon 
 *
 *
 */

/*! \file server.h
 *  \brief network server*/

#ifndef _ASPAMD_SERVER_
#define _ASPAMD_SERVER_

#include "net.h"

gint aspamd_start_server (aspamd_server_t *server);
gint aspamd_server_run (aspamd_server_t *server);
gint aspamd_server_close_session (aspamd_server_t *server, aspamd_session_t *session);
void aspamd_stop_server (aspamd_server_t *server);

#endif


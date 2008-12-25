/* 
 * aspamd - advanced spam daemon 
 *
 */

/*! \file session.h
 *  \brief session handling */

#ifndef _ASPAMD_SESSION_
#define _ASPAMD_SESSION_

#include "net.h"

gint aspamd_start_session (aspamd_server_t *server, int socket,
			   aspamd_session_t **new_session);
void aspamd_close_session (aspamd_session_t *session);
gint aspamd_session_read_callback (aspamd_session_t *session);

#endif

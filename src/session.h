/* 
 * aspamd - advanced spam daemon 
 *
 */

/*! \file session.h
 *  \brief session handling */

#ifndef _ASPAMD_SESSION_
#define _ASPAMD_SESSION_

#include "net.h"

#define ASSASSIN_VER_MAJOR		1
#define ASSASSIN_VER_MINOR		4

enum aspamd_session_state
{
	aspamd_session_st_head,
	aspamd_session_st_body,
	aspamd_session_st_response,
	aspamd_session_st_err,
	aspamd_session_st_closed
};

typedef enum session_state session_state_t;

gint aspamd_start_session (aspamd_server_t *server, int socket,
			   aspamd_session_t **new_session);
void aspamd_close_session (aspamd_session_t *session);
gint aspamd_session_read_callback (aspamd_session_t *session);
gint aspamd_session_reply_callback (aspamd_session_t *session, assassin_message_t *reply);

#endif

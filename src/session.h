/* 
 * aspamd - advanced spam daemon 
 *
 */

/*! \file session.h
 *  \brief session handling */

#ifndef _ASPAMD_SESSION_
#define _ASPAMD_SESSION_

#include <parser.h>

/** structure to keep client session data */
struct aspamd_session
{
	GMutex *lock;
	/*!< lock to protect session because it is accessed by the
	 * KAS threads and main program thread */
	volatile gint refs;
	/*!< reference count to the current session */
	int socket;
	/*!< socket file descriptor */
	gchar *buffer;
	/*!< buffer to keep incoming data */
	gint size;
	/*!< buffer size */
	gint filling;
	/*!< filling in the header buffer */
	gint offset;
	/*!< offset to run parser */
	struct aspamd_server *parent;
	/*!< pointer to server which accepted this session*/
	assassin_parser_t *parser;
	/*!< parser to parse incoming data */
	gint head;
	assassin_message_t *request;
	/*!< parsed SpamAssassin message */
	gint quarantine;
	gint bytes_read, bytes_written;
	gint cleaned;
};
typedef struct aspamd_session aspamd_session_t;

gint aspamd_session_allocate (aspamd_session_t **new_session,
			      struct aspamd_server *server, int socket);
void aspamd_session_ref (aspamd_session_t *session);
gint aspamd_session_start (aspamd_session_t *session);
gint aspamd_session_stop (aspamd_session_t *session);
gint aspamd_session_reply (aspamd_session_t *session, assassin_message_t *reply,
			   gint scan_id);
void aspamd_session_unref (aspamd_session_t *session);
void session_free (aspamd_session_t *session);

#endif

/* 
 * aspamd - advanced spam daemon 
 *
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <glib.h>
#include "server.h"
#include "session.h"
#include "errors.h"
#include "assassin.h"

/** @brief allocates session
 *
 * constructs session structure and allocates internal buffers and
 * structures.
 *
 * @param server server data
 * @param socket session socket descriptor
 * @param new_session newly allocated session structure
 * @return an error code
 */

gint aspamd_start_session (aspamd_server_t *server, int socket,
			   aspamd_session_t **new_session)
{
	aspamd_session_t *session;
	gint ret = ASPAMD_ERR_OK;

	g_assert (server);
	g_assert (socket > 0);

	session = g_slice_new (aspamd_session_t);
	if (!session)
	{
		g_critical ("memory allocation failed");
		ret = ASPAMD_ERR_MEM;
		goto at_exit;
	}
	session->socket = socket;

	session->header_buffer = g_slice_alloc0 (ASSASSIN_MAX_HEAD_SIZE);
	if (!session->header_buffer)
	{
		g_critical ("memory allocation failed");
		ret = ASPAMD_ERR_MEM;
		goto at_exit;
	}
	session->header_offset = 0;
	session->parent = server;

at_exit:
	if (ret == ASPAMD_ERR_OK)
		*new_session = session;
	else
	{
		if (session)
			aspamd_close_session (session);
		*new_session = NULL;
	}
	return ASPAMD_ERR_OK;
}

/** @brief closes session
 *
 * releases all allocated resources and session structure itself.
 *
 * @param session session to be closed
 * @return an error code
 */

void aspamd_close_session (aspamd_session_t *session)
{
	g_assert (session);

	if (session->socket > 0)
	{
		shutdown (session->socket, SHUT_RDWR);
		g_debug ("socket %i is shut down", session->socket);
		close (session->socket);
		session->socket = 0;
	}
	if (session->header_buffer)
	{
		g_slice_free1 (ASSASSIN_MAX_HEAD_SIZE,
			       session->header_buffer);
		session->header_buffer = NULL;
	}
	g_slice_free1 (sizeof (aspamd_session_t), session);	
}

/** @brief incoming data handler
 *
 * initiated when data is available on the socket. reads data from
 * socket and passes on the the parser.
 *
 * @param session session data
 * @return an error code
 */

gint aspamd_session_read_callback (aspamd_session_t *session)
{
	gint bytes_read;

	g_assert (session);

	bytes_read = read (session->socket, session->header_buffer + session->header_offset, 
			   ASSASSIN_MAX_HEAD_SIZE - session->header_offset);
	if (bytes_read == -1)
	{
		g_critical ("read from socket %i failed: %s", session->socket,
			    strerror (errno));
		return ASPAMD_ERR_NET;
	}
	/* connection has been closed on the other side */
	else if (bytes_read == 0)
		return aspamd_server_close_session (session->parent, session);

	session->header_offset += bytes_read;
	g_debug ("%i bytes read from socket %i", bytes_read, session->socket);
	
	/*------------------------------------------------------------------*/
	/* stub to test server a little bit */

	if (session->header_offset >= ASSASSIN_MAX_HEAD_SIZE / 2)
	{
		g_debug ("more then 10 bytes read, session is about to be closed");
		
		/* echo */
		write (session->socket, session->header_buffer, session->header_offset);

		return aspamd_server_close_session (session->parent, session);
	}

	/* end of the stub */
	/*------------------------------------------------------------------*/

	return ASPAMD_ERR_OK;
}

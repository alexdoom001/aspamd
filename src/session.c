/* 
 * aspamd - advanced spam daemon 
 *
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <glib.h>
#include <server.h>
#include <session.h>
#include <errors.h>
#include <assassin.h>
#include <parser.h>

static gint aspamd_session_check_msg_sanity (assassin_message_t *msg, gchar **explanation)
{
	g_assert (msg && explanation);

	if (msg->version_minor < ASSASSIN_VER_MINOR || 
	    msg->version_major < ASSASSIN_VER_MAJOR)
	{
		g_warning ("message %p has unsupported protocol version", msg);
		*explanation = "protocol version is unsupported\r\n";
		return assassin_ex_protocol;
	}

	if (msg->command != assassin_cmd_check && 
	    msg->command != assassin_cmd_process && 
	    msg->command != assassin_cmd_ping)
	{
		g_warning ("message %p command is unsupported", msg);
		*explanation = "command is unsupported\r\n";
		return assassin_ex_protocol;
	}
	
	return assassin_ex_ok;
}

static gint aspamd_session_process_message (aspamd_session_t *session, gint error)
{
	gint ret = ASPAMD_ERR_OK;
	assassin_message_t *request = NULL, *reply = NULL;
	gboolean sanity = assassin_ex_ok;
	gchar *body = "";
	gchar *buffer = NULL;
	gint filling = 0;
	gint bytes_written;

	g_assert (session);

	request = assassin_parser_get (session->parser);

	if (request && error == ASPAMD_ERR_OK)
	{
		sanity = aspamd_session_check_msg_sanity (request, &body);
		if (sanity != assassin_ex_ok)
		{
			ret = assassin_msg_allocate (&reply, assassin_msg_response,
						     request->command, ASSASSIN_VER_MAJOR,
						     ASSASSIN_VER_MINOR);
			ASPAMD_ERR_CHECK (ret);
		}
		else
		{
			if (request->command == assassin_cmd_ping)
			{
				ret = assassin_msg_allocate (&reply, assassin_msg_response,
						     request->command, ASSASSIN_VER_MAJOR,
						     ASSASSIN_VER_MINOR);
				ASPAMD_ERR_CHECK (ret);
			}
			else
			{
				g_debug ("KAS stub");

				/*----------------------------------------------------------*/
				/* Actually it should be replaced by the call
				 * to the KAS */

				ret = assassin_msg_allocate (&reply, assassin_msg_response,
							     request->command,
							     ASSASSIN_VER_MAJOR,
							     ASSASSIN_VER_MINOR);
				ASPAMD_ERR_CHECK (ret);

				/*----------------------------------------------------------*/
			}
		}
	}
	else
	{
		ret = assassin_msg_allocate (&reply, assassin_msg_response,
					     -1, ASSASSIN_VER_MAJOR,
					     ASSASSIN_VER_MINOR);
		ASPAMD_ERR_CHECK (ret);
		body = "request is malformed\r\n";
	}

	switch (error)
	{
	case ASPAMD_ERR_OK:
		reply->error = sanity;
		break;
	case ASPAMD_ERR_MEM:
		reply->error = assassin_ex_oserr;
		break;
	case ASPAMD_ERR_PARSER:
		reply->error = assassin_ex_protocol;
		break;
	default:
		reply->error = assassin_ex_software;
	}

	if (strlen (body) > 0)
	{
		ret = assassin_msg_add_header (reply, assassin_hdr_content_length,
					       g_variant_new_int32 (strlen (body)));
		ASPAMD_ERR_CHECK (ret);

		ret = assassin_msg_add_body (reply, body, 0, strlen (body), FALSE);
		ASPAMD_ERR_CHECK (ret);
	}

	ret = assassin_msg_printf (reply, (gpointer *)&buffer, &filling);
	ASPAMD_ERR_CHECK (ret);

	bytes_written = write (session->socket, buffer, filling);
	if (bytes_written == -1)
	{
		g_critical ("write into socket %i error: %s",
			    session->socket, strerror (errno));
		ret = ASPAMD_ERR_NET;
		goto at_exit;
	}
	ret = aspamd_server_close_session (session->parent, session);
	ASPAMD_ERR_CHECK (ret);

at_exit:
	if (buffer)
		g_free (buffer);
	if (reply)
		assassin_msg_free (reply);
	if (request)
		assassin_msg_free (request);
	return ret;
}

/*-----------------------------------------------------------------------------*/

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

	session->buffer = g_slice_alloc0 (ASSASSIN_MAX_HEAD_SIZE);
	if (!session->buffer)
	{
		g_critical ("memory allocation failed");
		ret = ASPAMD_ERR_MEM;
		goto at_exit;
	}
	session->size = ASSASSIN_MAX_HEAD_SIZE;
	session->filling = 0;
	session->offset = 0;
	session->head_allocated = 1;
	session->parent = server;
	session->state = aspamd_session_st_head;

	ret = assassin_parser_allocate (&session->parser, assassin_msg_request, 0);
	ASPAMD_ERR_CHECK (ret);

	g_debug ("session %p is allocated: parser - %p, buffer - %p, socket - %i", session,
		 session->parser, session->buffer, session->socket);
	
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

	g_debug ("session %p is about to be released", session);
	if (session->socket > 0)
	{
		shutdown (session->socket, SHUT_RDWR);
		g_debug ("socket %i is shut down", session->socket);
		close (session->socket);
		session->socket = 0;
	}
	if (session->buffer)
	{
		if (session->head_allocated)
			g_slice_free1 (ASSASSIN_MAX_HEAD_SIZE,
				       session->buffer);
		else
			g_free (session->buffer);
		session->buffer = NULL;
	}
	if (session->parser)
	{
		assassin_parser_free (session->parser);
		session->parser = NULL;
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
	gint	ret = ASPAMD_ERR_OK,
		bytes_read = 0,
		completed = 0,
		bytes_relocated = 0;
	gchar	*body = NULL;

	g_assert (session);

	if (session->state != aspamd_session_st_head &&
	    session->state != aspamd_session_st_body)
	{
		g_critical ("some data arrived on socket %i but session is already handled",
			session->socket);
		return aspamd_server_close_session (session->parent, session);
	}

	if (session->size)
	{
		bytes_read = read (session->socket, session->buffer + session->filling, 
				   session->size);
		if (bytes_read == -1)
		{
			g_critical ("read from socket %i failed: %s", session->socket,
				    strerror (errno));
			return ASPAMD_ERR_NET;
		}
		/* connection has been closed on the other side */
		else if (bytes_read == 0)
			return aspamd_server_close_session (session->parent, session);

		session->filling += bytes_read;
		session->size -= bytes_read;
		g_debug ("%i bytes read from socket %i", bytes_read, session->socket);
	}
	else
	{
		g_critical ("no free space in the buffer to handle incoming data\
 on socket %i",session->socket);
		return aspamd_server_close_session (session->parent, session);
	}
	
	ret = assassin_parser_scan(session->parser,
				   session->buffer,
				   &session->offset,
				   session->filling,
				   &completed, 0);
	if (ret != ASPAMD_ERR_OK || completed)
		return aspamd_session_process_message (session, ret);

	if (session->state == aspamd_session_st_head)
	{
		if (session->parser->state == assassin_prs_body)
		{
			bytes_relocated = session->filling - session->offset;
			session->size = MAX(session->parser->body_size,
					    bytes_relocated);
			body = g_malloc (session->size);
			if (!body)
			{
				g_critical ("memory allocation failed");
				return aspamd_session_process_message (session,
								       ASPAMD_ERR_MEM);
			}
			if (bytes_relocated > 0)
			{
				memcpy (body, session->buffer + session->offset,
					bytes_relocated);
				g_debug ("%i bytes has been relocated to the new\
 buffer which size is %i bytes, address %p", bytes_relocated, session->size, body);
				session->filling = bytes_relocated;
				session->size -= bytes_relocated;
			}
			else
				session->filling = 0;

			session->offset = 0;
			g_slice_free1 (ASSASSIN_MAX_HEAD_SIZE,
				       session->buffer);
			session->head_allocated = 0;
			session->buffer = body;

			session->state = aspamd_session_st_body;
		}

	}

	return ASPAMD_ERR_OK;
}

gint aspamd_session_reply_callback (aspamd_session_t *session, assassin_message_t *reply)
{
	gint ret = ASPAMD_ERR_OK;
	return ret;
}

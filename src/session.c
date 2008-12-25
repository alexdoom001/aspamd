/* 
 * aspamd - advanced spam daemon 
 *
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <glib.h>
#include <errors.h>
#include <assassin.h>
#include <parser.h>
#include <kas.h>
#include <server.h>
#include <session.h>
#include <config.h>

static gint session_close (aspamd_session_t *session);
static gint session_stop_close (aspamd_session_t *session);

static gint session_write (aspamd_session_t *session, assassin_message_t *msg)
{
	gint ret = ASPAMD_ERR_OK;
	gint bytes_written;
	assassin_buffer_t *buffer;

	ret = assassin_msg_print (msg, &buffer, ASSASSIN_BUF_NEW);
	ASPAMD_ERR_CHECK (ret);

	bytes_written = send (session->socket,
			      buffer->data + buffer->offset,
			      buffer->size, MSG_NOSIGNAL);
	ASPAMD_ERR_IF (bytes_written == -1, ASPAMD_ERR_IO,
		       "session %p: write into socket %i error: %s",
		       session, session->socket, strerror (errno));
	g_debug ("session %p: %i bytes are written to the socket %i",
		 session, bytes_written, session->socket);
	session->bytes_written += bytes_written;
at_exit:
	if (buffer)
		assassin_buffer_free (buffer);
	if (msg)
		assassin_msg_free (msg);
	session_stop_close (session);
	return ret;
}

static gint session_check_msg_sanity (aspamd_session_t *session, assassin_message_t *msg,
				      gchar **info)
{
	g_assert (msg && info);

	if (msg->version_major != 1 ||
	    msg->version_minor < 2 || msg->version_minor > 4)
	{
		g_warning ("session %p: message %p has unsupported protocol version",
			   session, msg);
		*info = "protocol version is unsupported\r\n";
		return assassin_ex_protocol;
	}

	switch (msg->command)   
	{
	case assassin_cmd_ping:
		*info = "";
		break;
	case assassin_cmd_check:
	case assassin_cmd_process:
	{
		if (!msg->content)
		{
			g_warning ("session %p: body is missing", session);
			*info = "message body is missing\r\n";
			return assassin_ex_protocol;
		}
		break;
	}
	default:
		g_warning ("session %p: message %p command is unsupported", session, msg);
		*info = "command is unsupported\r\n";
		return assassin_ex_protocol;
	}
	
	return assassin_ex_ok;
}

static gint session_process_message (aspamd_session_t *session, gint error, const gchar *info)
{
	gint ret = ASPAMD_ERR_OK;
	assassin_message_t *request = NULL, *reply = NULL;
	gboolean sanity = assassin_ex_ok;
	gchar *body = NULL;

	g_assert (session);

	request = assassin_parser_get (session->parser);

	if (request && error == ASPAMD_ERR_OK)
	{
		sanity = session_check_msg_sanity (session, request, &body);
		if (sanity != assassin_ex_ok)
		{
			ret = assassin_msg_allocate (&reply, assassin_msg_reply, NULL);
			ASPAMD_ERR_CHECK (ret);
			reply->command = request->command;
		}
		else
		{
			g_assert (session->parent);

			if (request->command == assassin_cmd_ping ||
			    session->parent->stub)
			{
				if (request->command != assassin_cmd_ping)
				{
					g_message ("legitimate message will not be passed "
						   "to the KAS engine because of stub mode");
					body = "this is a stub message\r\n";
				}
				ret = assassin_msg_allocate (&reply, assassin_msg_reply,
							     NULL);
				ASPAMD_ERR_CHECK (ret);
				reply->command = request->command;
				reply->version_minor = request->version_minor;
				reply->version_major = request->version_major;
			}
			else
			{
				session->request = request;
				ret = aspamd_kas_check (session->parent->kas, session,
							request, NULL);
				if (ret == ASPAMD_ERR_OK)
				{
					session->refs++;
					g_debug ("session %p: message passed to KAS, "
						 "refs - %i", session, session->refs);
				}
				return ret;
			}
		}
	}
	else
	{
		ret = assassin_msg_allocate (&reply, assassin_msg_reply, NULL);
		ASPAMD_ERR_CHECK (ret);
		if (info)
			body = (gchar *) info;
		else
			body = "";
	}

	switch (error)
	{
	case ASPAMD_ERR_OK:
		reply->error = sanity;
		break;
	case ASPAMD_ERR_MEM:
		reply->error = assassin_ex_oserr;
		if (!body)
			body = "memory allocation error\r\n";
		break;
	case ASPAMD_ERR_PARSER:
		reply->error = assassin_ex_protocol;
		if (!body)
			body = "message parsing error\r\n";
		break;
	case ASPAMD_ERR_IO:
		reply->error = assassin_ex_ioerr;
		if (!body)
			body = "IO error\r\n";
		break;
	default:
		reply->error = assassin_ex_software;
	}

	g_assert (body);
	if (strlen (body) > 0)
	{
		ret = assassin_msg_add_body (reply, body, 0, strlen (body), FALSE);
		ASPAMD_ERR_CHECK (ret);
	}

	ret = session_write (session, reply);
	ASPAMD_ERR_CHECK (ret);

at_exit:
	if (request)
		assassin_msg_free (request);
	return ret;
}

static gint session_fill_buffer (aspamd_session_t *session, aspamd_reactor_io_t *io)
{
	gint	ret = ASPAMD_ERR_OK,
		bytes_read = 0,
		bytes_relocated = 0;
	gchar	*body = NULL;

	if (session->parser->state == assassin_prs_body && session->head)
	{
		bytes_relocated = session->filling - session->offset;
		session->size = MAX(session->parser->body_size,
				    bytes_relocated);
		body = g_malloc (session->size);
		if (!body)
		{
			g_critical ("session %p: data buffer allocation failed",
				    session);
			ret = session_process_message (session, ASPAMD_ERR_MEM,
						       "failed to allocate buffer to fit "
						       "message body\r\n");
			goto at_exit;
		}
		if (bytes_relocated > 0)
		{
			memcpy (body, session->buffer + session->offset,
				bytes_relocated);
			g_debug ("session %p: %i bytes has been relocated to the new\
 buffer which size is %i bytes, address %p", session, bytes_relocated, session->size, body);
			session->filling = bytes_relocated;
			session->size -= bytes_relocated;
		}
		else
			session->filling = 0;

		session->offset = 0;
		g_slice_free1 (ASSASSIN_MAX_HEAD_SIZE,
			       session->buffer);
		session->head = 0;
		session->buffer = body;
	}

	if (session->size)
	{
		bytes_read = read (session->socket, session->buffer + session->filling, 
				   session->size);
		ASPAMD_ERR_IF (bytes_read == -1,
			       ASPAMD_ERR_IO, "session %p: failed to read data from socket %i: %s",
			       session, session->socket, strerror (errno));
		if (bytes_read == 0)
		{
			g_critical ("session %p: remote side closed the connection", session);
			session_stop_close (session);
		}
		else
		{
			session->filling += bytes_read;
			session->size -= bytes_read;
			g_debug ("session %p: bytes read - %i, buffer filling - %i, "
				 "free space - %i",session, bytes_read,
				 session->filling, session->size);
		}
	}
	else
	{
		g_critical ("session %p: no free space in the buffer", session);
		ret = session_process_message (session, ASPAMD_ERR_ERR,
					       "no free space in the buffer to read data "
					       "and continue parsing\r\n");
	}
	session->bytes_read += bytes_read;
at_exit:
	return ret;
}

static gint session_idle (aspamd_session_t *session, gint fd, gint *timeout)
{
	g_assert (session && timeout);

	g_mutex_lock (session->lock);
	g_warning ("session %p: message read timeout", session);
	*timeout = -1;
	session_process_message (session, ASPAMD_ERR_IO, "message read timeout\r\n");
	g_mutex_unlock (session->lock);
	return ASPAMD_REACTOR_OK;
}

static gint session_io (aspamd_session_t *session, gint fd, aspamd_reactor_io_t *io)
{
	gint ret = ASPAMD_ERR_OK,
		completed = 0;

	g_assert (session && io);

	if(g_mutex_trylock (session->lock))
	{
		if (io->events & (POLLHUP | POLLERR))
		{
			if(io->events & POLLHUP)
				g_warning ("session %p: remote side closed the session",
					   session);
			else
				g_critical ("session %p: error occurs during IO on socket %i",
					    session, session->socket);
			ret = ASPAMD_ERR_NET;
			session_stop_close (session);
		}
		else
		{
			ret = session_fill_buffer (session, io);
			ASPAMD_ERR_CHECK (ret);
			ret = assassin_parser_scan(session->parser, session->buffer,
						   &session->offset, session->filling,
						   &completed, 0);
			if (ret != ASPAMD_ERR_OK || completed)
			{
				g_debug ("session %p: parser error - %i, completed - %i",
					 session, ret, completed);
				ret = aspamd_reactor_on_idle (session->parent->reactor,
							      session->socket, NULL, -1);
				ASPAMD_ERR_CHECK (ret);
				io->mask &= ~(POLLIN | POLLPRI);
				ret = session_process_message (session, ret, NULL);
			}		
		}
at_exit:
		g_mutex_unlock (session->lock);
	}
	if (ret == ASPAMD_ERR_OK)
		return ASPAMD_REACTOR_OK;
	else
		return ASPAMD_REACTOR_ERR;
}

static gint session_stop_close (aspamd_session_t *session)
{
	gint ret = ASPAMD_ERR_OK;

	g_assert (session);

	aspamd_server_detach (session->parent, session);
	ret = aspamd_reactor_remove (session->parent->reactor,
				     session->socket, session);
	if (ret == ASPAMD_ERR_OK)
	{
		session->refs--;
		g_debug ("session %p: stopped, refs - %i", session, session->refs);
	}
	session_close (session);

	return ret;
}

static gint session_close (aspamd_session_t *session)
{
	gint ret = ASPAMD_ERR_OK;

	g_assert (session);

	if (session->socket > 0 && session->refs <= 1)
	{
		if (shutdown (session->socket, SHUT_RDWR) == -1)
		{
			g_warning ("session %p: failed to shutdown socket %i: %s", session,
				   session->socket, strerror (errno));
			ret = ASPAMD_ERR_NET;
		}
		else
			g_debug ("session %p: socket %i is shut down", session,
				 session->socket);
		close (session->socket);
		session->socket = 0;
	}
	return ret;
}

static void session_clean (aspamd_session_t *session)
{
	g_assert (session);

	g_debug ("session at %p is about to be released", session);
	if (session->buffer)
	{
		if (session->head)
			g_slice_free1 (ASSASSIN_MAX_HEAD_SIZE,
				       session->buffer);
		else
			g_free (session->buffer);
			
		session->buffer = NULL;
	}
	if (session->request)
	{
		assassin_msg_free (session->request);
		session->request = NULL;
	}
	if (session->parser)
	{
		assassin_parser_free (session->parser);
		session->parser = NULL;
	}
	if (session->lock)
	{
		g_mutex_free (session->lock);
		session->lock = NULL;
	}
	session->cleaned = 1;
}

void session_free (aspamd_session_t *session)
{
	g_slice_free1 (sizeof (aspamd_session_t), session);
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

gint aspamd_session_allocate (aspamd_session_t **new_session, aspamd_server_t *server,
			      int socket)
{
	aspamd_session_t *session;
	gint ret = ASPAMD_ERR_OK;

	g_assert (server);
	g_assert (socket > 0);

	session = g_slice_new (aspamd_session_t);
	ASPAMD_ERR_IF (!session, ASPAMD_ERR_MEM, "session allocation failed");
	session->socket = socket;

	session->buffer = g_slice_alloc0 (ASSASSIN_MAX_HEAD_SIZE);
	ASPAMD_ERR_IF (!session->buffer, ASPAMD_ERR_MEM,
		       "session %p: data buffer allocation failed", session);

	session->lock = g_mutex_new ();
	ASPAMD_ERR_IF (!session->lock, ASPAMD_ERR_MEM,
		       "session %p: mutex allocation failed", session);

	session->size = ASSASSIN_MAX_HEAD_SIZE;
	session->filling = 0;
	session->offset = 0;
	session->head = 1;
	session->parent = server;
	session->refs = 1;
	session->request = NULL;
	session->quarantine = 0;
	session->cleaned = 0;

	ret = assassin_parser_allocate (&session->parser, assassin_msg_request, 0);
	ASPAMD_ERR_CHECK (ret);

	g_debug ("session at %p is allocated: socket - %i, parser - %p, buffer - %p",
		 session, session->socket, session->parser, session->buffer);
	
at_exit:
	if (ret == ASPAMD_ERR_OK)
		*new_session = session;
	else
	{
		if (session)
			aspamd_session_unref (session);
		*new_session = NULL;
	}
	return ASPAMD_ERR_OK;
}

/** @brief increases the reference count
 *
 * @param session session
 */

void aspamd_session_ref (aspamd_session_t *session)
{
	g_assert (session);

	g_mutex_lock (session->lock);
	session->refs ++;
	g_debug ("session %p: refs - %i", session, session->refs);
	g_mutex_unlock (session->lock);
}

gint aspamd_session_start (aspamd_session_t *session)
{
	gint ret = ASPAMD_ERR_OK;

	ret = aspamd_reactor_add (session->parent->reactor, session->socket, 
				  POLLERR | POLLIN | POLLPRI | POLLHUP,
				  session);
	ASPAMD_ERR_CHECK (ret);
	aspamd_session_ref (session);
	ret = aspamd_reactor_on_io (session->parent->reactor, session->socket, 
				    (aspamd_reactor_cbck_t)&session_io, 0);
	ASPAMD_ERR_CHECK (ret);
	ret = aspamd_reactor_on_idle (session->parent->reactor, session->socket, 
				      (aspamd_reactor_cbck_t)&session_idle, 
				      session->parent->timeout);
	ASPAMD_ERR_CHECK (ret);
	g_debug ("session %p: started", session);
	session->bytes_written = 0;
	session->bytes_read = 0;
at_exit:
	if (ret != ASPAMD_ERR_OK)
		session_process_message (session, ret, "maximum number of connections is "
					 "achieved\r\n");
	return ret;
}

gint aspamd_session_stop (aspamd_session_t *session)
{
	gint ret = ASPAMD_ERR_OK;

	g_mutex_lock (session->lock);
	ret = aspamd_reactor_remove (session->parent->reactor,
				     session->socket, session);
	if (ret == ASPAMD_ERR_OK)
		session->refs--;
	session_close (session);
	g_mutex_unlock (session->lock);

	return ret;
}

/** @brief callback initiated to write reply and close session
 *
 * @param session session data
 * @reply reply a reply to be written
 * @scan_id KAS scan ID
 * @return an error code
 */

gint aspamd_session_reply (aspamd_session_t *session, assassin_message_t *reply,
			   gint scan_id)
{
	gint ret = ASPAMD_ERR_OK;

	g_assert (session && reply);

	g_mutex_lock (session->lock);

	if (session->request)
	{
		assassin_msg_free (session->request);
		session->request = NULL;
	}

	ret = session_write (session, reply);
	ASPAMD_ERR_CHECK (ret);
at_exit:
	g_mutex_unlock (session->lock);
	return ret;
}

/** @brief decreases the reference count
 *
 * if reference count is equal to zero then session is released
 *
 * @param session session
 */

void aspamd_session_unref (aspamd_session_t *session)
{
	g_assert (session);

	g_mutex_lock (session->lock);
	if (session->refs > 0)
	{
		session->refs --;
		g_debug ("session %p: refs - %i", session, session->refs);
	}
	g_mutex_unlock (session->lock);

	if (session->refs == 0)
	{
		session_close (session);
		session_clean (session);

		if (session->quarantine)
			session->parent->sessions_to_free = g_slist_append (session->parent->sessions_to_free, session);
		else
			session_free (session);
	}
}

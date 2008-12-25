/* 
 * aspamd - advanced spam daemon 
 *
 */

#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <glib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "server.h"
#include "errors.h"
#include "session.h"

#define ASPAMD_NET_POLL_FD	(ASPAMD_NET_MAX_CON + 1)

/** @brief fcntl wrapper
 *
 * reads current flags, add new flags using 'or' operation and writes
 * it back.
 *
 * @param socket socket descriptor
 * @param option option to be enabled
 * @return an error code
 */

static gint aspamd_fcntl(int socket, int option)
{
	int cur_options;

	g_assert (socket > 0);

	cur_options = fcntl (socket, F_GETFL);
	if (cur_options < 0)
	{
		g_critical ("get socket %i options failed", socket);
		return ASPAMD_ERR_NET;
	}
	cur_options |= option;
	if (fcntl(socket, F_SETFL, cur_options) < 0)
	{
		g_critical ("set socket %i options failed", socket);
		return ASPAMD_ERR_NET;
	}

	return ASPAMD_ERR_OK;
}

/** @brief server idle handler
 *
 * launched when there are no active tasks at the moment to do some
 * real-time uncritical things like a garbage collection.
 *
 * @param server server data
 * @return an error code
 */

static gint aspamd_server_idle (aspamd_server_t *server)
{
	g_assert (server);

	return ASPAMD_ERR_OK;
}

/** @brief accepts new connection
 *
 * checks connection limit and accepts new connections. if there are
 * no free slots then server socket polling will be disabled until
 * some client sessions will not be terminated.
 *
 * @param server server data
 * @return an error code
 */

static gint aspamd_server_accept (aspamd_server_t *server)
{
	gint ret = ASPAMD_ERR_OK;
	int i, sock;
	struct pollfd *poll_fd = NULL,
		*empty_poll_fd = NULL;
	struct sockaddr_in remote_addr;
	socklen_t addr_size = sizeof (struct sockaddr_in);
	aspamd_session_t *session;

	poll_fd = &server->poll_fds[0];

	if (poll_fd->revents & POLLERR)
	{
		g_critical ("accept faild on socket %i", server->socket);
		return ASPAMD_ERR_NET;
	}

	/* if there are no free slots I have to disable server socket
	 * polling */
	if(server->num_fds == ASPAMD_NET_POLL_FD)
	{
		g_critical ("maximum number of clients is achieved, connection refused");
		poll_fd->events = 0;
		return ASPAMD_ERR_NET;
	}

	for (i = 1, empty_poll_fd = NULL; i < ASPAMD_NET_POLL_FD; i++)
	{
		empty_poll_fd = &server->poll_fds[i];
		if (empty_poll_fd->fd == 0)
			break;
	}

	g_assert (empty_poll_fd->fd == 0);

	sock = accept (server->socket, (struct sockaddr *)&remote_addr,
		       &addr_size);

	g_assert (sock > 0);

	g_debug ("connection from %s:%i accepted, socket: %i",
		 inet_ntoa (remote_addr.sin_addr),
		 ntohs (remote_addr.sin_port),
		 sock);
	ret = aspamd_fcntl (sock, O_NONBLOCK);
	ASPAMD_ERR_CHECK (ret);
	ret = aspamd_start_session (server, sock, &session);
	ASPAMD_ERR_CHECK (ret);
	empty_poll_fd->fd = sock;
	empty_poll_fd->events = POLLIN | POLLPRI | POLLERR;
	empty_poll_fd->revents = 0;

	/* tricky function, it differs same values placed in different
	* memory regions */

	g_hash_table_insert (server->sessions_by_fd, &empty_poll_fd->fd, session);

	server->num_fds++;
	poll_fd->revents = 0;
at_exit:
	return ret;
}

/*-----------------------------------------------------------------------------*/

/** @brief initializes server and prepares one for start
 *
 * opens server socket, binds one, makes it unblocking. creates array
 * of poll structures and hash table to find out the opened sessions
 * quickly.
 *
 * @param server server data
 * @return an error code
 */

gint aspamd_start_server (aspamd_server_t *server)
{
	gint ret = ASPAMD_ERR_OK;
	struct sockaddr_in sock_addr;
	int opt;

	g_assert (server);

	server->socket = socket (AF_INET, SOCK_STREAM, 0);
	if (server->socket == -1)
	{
		g_critical ("failed to create socket: %s",
			    strerror (errno));
		ret = ASPAMD_ERR_NET;
		goto at_exit;
	}
	g_debug ("socket opened: %i", server->socket);

	opt = 1;
	if (setsockopt(server->socket, SOL_SOCKET, SO_REUSEADDR,
		       &opt, sizeof(opt)) == -1)
	{
		g_critical ("failed to set socket %i option: %s",
			    server->socket, strerror (errno));
		ret = ASPAMD_ERR_NET;
		goto at_exit;
	}

	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_port = htons(server->port);
	sock_addr.sin_family = AF_INET;
	if(inet_aton (server->ip, &sock_addr.sin_addr) < 0)
	{
		g_critical ("failed to form socket %i addr from string %s",
			    server->socket, server->ip);
		ret = ASPAMD_ERR_NET;
		goto at_exit;
	}

	if (bind(server->socket, (struct sockaddr *) &sock_addr,
		 sizeof(sock_addr)) == -1)
	{
		g_critical ("failed to bind socket %i: %s",
			    server->socket, strerror (errno));
		ret = ASPAMD_ERR_NET;
		goto at_exit;
	}

	if(listen(server->socket, 16))
	{
		g_critical ("failed to start listening on socket %i: %s",
			    server->socket, strerror (errno));
		ret = ASPAMD_ERR_NET;
		goto at_exit;
	}
	g_debug ("socket %i bound to %s:%i",
		 server->socket, server->ip, server->port);

	aspamd_fcntl (server->socket, O_NONBLOCK);
	ASPAMD_ERR_CHECK (ret);

	server->poll_fds = g_malloc0 (sizeof (struct pollfd) * ASPAMD_NET_POLL_FD); 
	if (!server->poll_fds)
	{
		g_critical ("memory allocation failed");
		ret = ASPAMD_ERR_MEM;
		goto at_exit;
	}

	server->poll_fds[0].fd = server->socket;
	server->poll_fds[0].events = POLLIN | POLLERR;
	server->poll_fds[0].revents = 0;
	server->num_fds = 1;

	server->sessions_by_fd =  g_hash_table_new (g_int_hash, g_int_equal);
	if (!server->sessions_by_fd)
	{
		g_critical ("memory allocation failed");
		ret = ASPAMD_ERR_MEM;
		goto at_exit;
	}

	server->running = 1;

at_exit:
	if (ret != ASPAMD_ERR_OK)
	{
		if (server->sessions_by_fd)
		{
			g_hash_table_destroy (server->sessions_by_fd);
			server->sessions_by_fd = 0;
		}
		if (server->poll_fds)
		{
			g_free (server->poll_fds);
			server->poll_fds = 0;
		}
		if (server->socket > 0)
		{
			close (server->socket);
			server->socket = 0;
		}
	}
	return ret;
}

/** @brief runs server 
 *
 * runs polling loop to handle socket events asynchronously. if there
 * is event on server socket then aspamd_server_accept is executed, if
 * there are no events at all (eg timeout occurs ) aspamd_server_idle
 * is executed. Otherwise session read call back is executed to handle
 * incoming data.
 *
 * @param server server data
 * @return an error code
 */

gint aspamd_server_run (aspamd_server_t *server)
{
	gint ret = ASPAMD_ERR_OK;
	struct pollfd *curr_poll_fd = NULL;
	int i, poll_ret;
	aspamd_session_t *session;

	g_assert (server);

	g_debug ("server on socket %i is ready to run", server->socket);

	for (;server->running;)
	{
		poll_ret = poll(server->poll_fds, ASPAMD_NET_POLL_FD,
				ASPAMD_NET_POLL_TIMEOUT);

		if (poll_ret == -1)
		{
			if (errno == EINTR)
				continue;
			else
			{
				g_critical ("polling error on socket %i: %s",
					    server->socket, strerror (errno));
				ret = ASPAMD_ERR_NET;
				goto at_exit;
			}
		}

		if (poll_ret == 0)
		{
			ret = aspamd_server_idle (server);
			ASPAMD_ERR_CHECK (ret);
			continue;
		}
		
		if (server->poll_fds[0].revents)
		{
			if(aspamd_server_accept (server) != ASPAMD_ERR_OK)
				continue;
		}

		for (i = 1; i < ASPAMD_NET_POLL_FD; i++)
		{
			curr_poll_fd = &server->poll_fds[i];
			if (curr_poll_fd->fd > 0 && curr_poll_fd->revents)
			{
				if (curr_poll_fd->revents & POLLERR)
				{
					g_critical ("socket %i error: %s",
						    curr_poll_fd->fd,
						    strerror (errno));
					aspamd_server_close_session (server, session);
					continue;
				}
				session = g_hash_table_lookup (server->sessions_by_fd,
							       &curr_poll_fd->fd);
				g_assert (session);
				ret = aspamd_session_read_callback (session);
				if (ret != ASPAMD_ERR_OK)
					aspamd_server_close_session (server, session);
				curr_poll_fd->revents = 0;
			}
		}
	}

at_exit:
	return ret;
}

/** @brief closes session
 *
 * removes session from polling list and executes aspamd_close_session
 * function to release allocated resources.
 *
 * @param server server data
 * @param session session to be closed
 * @return an error code
 */

gint aspamd_server_close_session (aspamd_server_t *server, aspamd_session_t *session)
{
	int i;
	struct pollfd *curr_poll_fd = NULL;

	g_assert (server && session);

	for (i = 1; i < ASPAMD_NET_POLL_FD; i++)
	{
		curr_poll_fd = &server->poll_fds[i];
		if (curr_poll_fd->fd == session->socket)
			break;
	}
	g_assert (curr_poll_fd->fd == session->socket);
	g_hash_table_remove (server->sessions_by_fd, &curr_poll_fd->fd);
	curr_poll_fd->fd = 0;
	curr_poll_fd->events = 0;
	curr_poll_fd->revents = 0;
	g_debug ("socket %i is removed from polling list", session->socket);
	aspamd_close_session (session);
	/* server socket polling is re-enabled if there are free slots
	 * to handle connection */
	if (server->num_fds < ASPAMD_NET_POLL_FD)
		server->poll_fds[0].events = POLLIN;
	server->num_fds--;
	return ASPAMD_ERR_OK;
}

/** @brief stops server
 *
 * releases resources allocated by server, cleans-up polling list and
 * other internal structures, closes server socket.
 *
 * @param server server data
 * @return an error code
 */

void aspamd_stop_server (aspamd_server_t *server)
{
	g_assert (server);

	gint foreach_lambda (gpointer key, gpointer value, gpointer user_data)
	{
		aspamd_close_session ((aspamd_session_t *)value);
		return TRUE;
	}

	if (server->sessions_by_fd)
	{
		g_hash_table_foreach_remove (server->sessions_by_fd, foreach_lambda, NULL);
		g_hash_table_destroy (server->sessions_by_fd);
		server->sessions_by_fd = 0;
	}

	if (server->poll_fds)
	{
		g_free (server->poll_fds);
		server->poll_fds = 0;
	}
	if (server->socket > 0)
	{
		shutdown (server->socket, SHUT_RDWR);
		g_debug ("socket %i is shut down", server->socket);
		close (server->socket);
		server->socket = 0;
	}
}

/* 
 * aspamd - advanced spam daemon 
 *
 */

#include <sys/signalfd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <glib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <kas.h>
#include <errors.h>
#include <session.h>
#include <server.h>
#include <time.h>
#include <config.h>

static const gchar *default_server_ip = ASPAMD_DEFAULT_SERVER_IP,
	*default_socket_path = ASPAMD_DEFAULT_SOCKET_PATH;

/*-----------------------------------------------------------------------------*/

static gint server_inet_socket (aspamd_server_t *server)
{
	gint ret = ASPAMD_ERR_OK;
	struct sockaddr_in sock_addr;
	int opt, err;

	server->socket = socket (AF_INET, SOCK_STREAM, 0);
	ASPAMD_ERR_IF (server->socket == -1, ASPAMD_ERR_NET,
		       "server %p: failed to create socket: %s",
		       server, strerror (errno));
	g_debug ("server %p: master socket %i is opened", server, server->socket);

	opt = 1;
	err = setsockopt(server->socket, SOL_SOCKET, SO_REUSEADDR,
			 &opt, sizeof(opt));
	ASPAMD_ERR_IF (err == -1, ASPAMD_ERR_NET,
		       "server %p: failed to set socket %i option: %s",
		       server, server->socket, strerror (errno));

	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_port = htons(server->port);
	sock_addr.sin_family = AF_INET;
	err = inet_aton (server->ip, &sock_addr.sin_addr);
	ASPAMD_ERR_IF (err < 0, ASPAMD_ERR_NET,
		       "server %p: failed to form socket %i addr from string `%s'",
		       server, server->socket, server->ip);

	err = bind(server->socket, (struct sockaddr *) &sock_addr,
		   sizeof(sock_addr));
	ASPAMD_ERR_IF (err == -1, ASPAMD_ERR_NET,
		       "server %p: failed to bind socket to %i:%s",
		       server, server->socket, strerror (errno));
	g_debug ("server %p: socket %i is bound to %s:%i",
		 server, server->socket, server->ip, server->port);
	server->type = ASPAMD_SERVER_INET;
at_exit:
	return ret;
}

static gint server_unix_socket (aspamd_server_t *server)
{
	gint ret = ASPAMD_ERR_OK;
	struct sockaddr_un sock_addr;
	int err;

	server->socket = socket (AF_UNIX, SOCK_STREAM, 0);
	ASPAMD_ERR_IF (server->socket == -1, ASPAMD_ERR_NET,
		       "server %p: failed to create socket: %s",
		       server, strerror (errno));
	g_debug ("server %p: master socket %i is opened", server, server->socket);

	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sun_family = AF_UNIX;
	strcpy(sock_addr.sun_path, server->sock_path);
	unlink(server->sock_path);

	err = bind(server->socket, (struct sockaddr *) &sock_addr,
		   sizeof(sock_addr));
	ASPAMD_ERR_IF (err == -1, ASPAMD_ERR_NET,
		       "server %p: failed to bind socket to %i: %s",
		       server, server->socket, strerror (errno));
	g_debug ("server %p: socket is bound to: %s",
		 server, server->sock_path);
	err = chmod (server->sock_path, S_IRWXU | S_IRWXG | S_IRWXO);
	ASPAMD_ERR_IF (err == -1, ASPAMD_ERR_ERR,
		       "server %p: failed to chmod the %s: %s",
		       server, server->sock_path, strerror (errno));
	server->type = ASPAMD_SERVER_UNIX;
at_exit:
	return ret;
}

/** @brief fcntl wrapper
 *
 * reads current flags, add new flags using 'or' operation and writes
 * it back.
 *
 * @param socket socket descriptor
 * @param option option to be enabled
 * @return an error code
 */

static gint server_fcntl(int socket, int option)
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

static gint server_accept (aspamd_server_t *server, gint fd, aspamd_reactor_io_t *io)
{
	gint ret = ASPAMD_ERR_OK;
	int sock;
	struct sockaddr_in remote_addr_in;
	struct sockaddr_un remote_addr_un;
	socklen_t addr_size = sizeof (struct sockaddr_in);
	aspamd_session_t *session = NULL;

	g_assert (server && io);

	if (io->events & POLLERR)
	{
		g_critical ("server %p: failed to accept connection on socket %i",
			    server, server->socket);
		aspamd_server_stop (server);
		aspamd_server_start (server, server->type, server->stub, server->timeout);
		goto at_exit;
	}

	if (server->type == ASPAMD_SERVER_INET)
	{
		sock = accept (server->socket, (struct sockaddr *)&remote_addr_in,
			       &addr_size);
		g_assert (sock > 0);
		g_debug ("server %p: accepted connection from %s:%i into socket %i",
			 server, inet_ntoa (remote_addr_in.sin_addr),
			 ntohs (remote_addr_in.sin_port), sock);
	}
	else
	{
		sock = accept (server->socket, (struct sockaddr *)&remote_addr_un,
			       &addr_size);
		g_assert (sock > 0);
		g_debug ("server %p: accepted connection into socket %i",
			 server, sock);
	}
	ret = server_fcntl (sock, O_NONBLOCK);
	ASPAMD_ERR_CHECK (ret);
	ret = aspamd_session_allocate (&session, server, sock);
	ASPAMD_ERR_CHECK (ret);
	ret = aspamd_session_start (session);
	ASPAMD_ERR_CHECK (ret);
	g_mutex_lock (server->lock);
	server->sessions = g_slist_append (server->sessions, session);
	server->accepted ++;
	g_mutex_unlock (server->lock);
at_exit:
	if (ret != ASPAMD_ERR_OK)
	{
		if (session)
			aspamd_session_unref (session);
	}
	return ASPAMD_REACTOR_OK;
}

static gint server_idle (aspamd_server_t *server, gint fd, gpointer stub)
{
	GSList *iter = NULL;
	g_assert (server);

	g_mutex_lock (server->lock);
	if (server->garbage)
	{
		g_debug ("server %p: starting garbage collection",
			server);
		for (iter = server->garbage; iter; iter = g_slist_next (iter))
			aspamd_session_unref (iter->data);
		g_slist_free (server->garbage);
		server->garbage = NULL;
	}
	g_mutex_unlock (server->lock);
	return ASPAMD_REACTOR_OK;
}

static void server_dump_stats (aspamd_server_t *server)
{
	gint sum = 0;
	GSList *iter = NULL;
	gint timestamp = 0;

	g_assert (server);

	timestamp = (gint)time (NULL);

	if (server->accepted)
	{
		g_message ("statistic of %i minutes uptime",
			   (timestamp - server->timestamp) / 60);
		g_message ("connections accepted - %i", server->accepted);
	}

	if (server->bytes_read)
	{
		for (iter = server->bytes_read; iter; iter = g_slist_next (iter))
			sum += (gint) iter->data;
		g_message ("average request size - %i bytes",
			 sum / g_slist_length (server->bytes_read));
		g_message ("incoming data bitrate - %i KBit",
			 8 * sum / ((timestamp - server->timestamp) * 1024));
		g_slist_free (server->bytes_read);
		server->bytes_read = NULL;
	}

	sum = 0;

	if (server->bytes_written)
	{
		for (iter = server->bytes_written; iter; iter = g_slist_next (iter))
			sum += (gint) iter->data;
		g_message ("average reply size - %i bytes",
			   sum / g_slist_length (server->bytes_written));
		g_message ("outgoing data bitrate - %i KBit",
			   8 * sum / ((timestamp - server->timestamp) * 1024));
		g_slist_free (server->bytes_written);
		server->bytes_written = NULL;
	}
	server->accepted = 0;
	server->timestamp = timestamp;
}


/*-----------------------------------------------------------------------------*/

aspamd_pair_t server_types[] = {
	{ASPAMD_SERVER_INET, "INET"},
	{ASPAMD_SERVER_UNIX, "UNIX"}
};

/** @brief allocates resources to run server
 *
 * @param new_server pointer to return allocated object
 * @return an error code
 */

gint aspamd_server_allocate (aspamd_server_t **new_server, aspamd_reactor_t *reactor,
			     kas_data_t *kas)
{
	gint ret = ASPAMD_ERR_OK;
	aspamd_server_t *server = NULL;

	g_assert (reactor);

	server = g_slice_new (aspamd_server_t);
	ASPAMD_ERR_IF (!server, ASPAMD_ERR_MEM,
		       "network server allocation failed");
	server->lock = g_mutex_new ();
	ASPAMD_ERR_IF (!server->lock, ASPAMD_ERR_MEM,
		       "server %p: mutex allocation failed", server);

	server->port = ASPAMD_DEFAULT_SERVER_PORT;
	server->ip = (gchar *) default_server_ip;
	server->sock_path = (gchar *) default_socket_path;
	server->socket = -1;
	server->kas = kas;
	server->sessions = NULL;
	server->sessions_to_free = NULL;
	server->garbage = NULL;
	server->reactor = reactor;
	server->timeout = ASPAMD_DEFAULT_TIMEOUT;
	server->accepted = 0;
	server->bytes_read = 0;
	server->bytes_written = 0;

	g_debug ("server at %p is allocated: ip - %s, port - %i, reactor - %p, kas - %p",
		 server, server->ip, server->port, server->reactor, server->kas);

at_exit:
	if (ret == ASPAMD_ERR_OK)
		*new_server = server;
	else
	{
		*new_server = NULL;
		if (server)
			aspamd_server_free (server);
	}
	return ret;
}

/** @brief initializes server and prepares one for start
 *
 * opens server socket, binds one, makes it unblocking.
 *
 * @param server server data
 * @return an error code
 */

gint aspamd_server_start (aspamd_server_t *server, gint type, gint stub, gint timeout)
{
	gint ret = ASPAMD_ERR_OK;
	gint err;

	g_assert (server);

	g_mutex_lock (server->lock);
	if (type == ASPAMD_SERVER_INET)
		ret = server_inet_socket (server);
	else if(type == ASPAMD_SERVER_UNIX)
		ret = server_unix_socket (server);
	else
		ret = ASPAMD_ERR_PARAM;
	ASPAMD_ERR_CHECK (ret);

	err = listen(server->socket, 16);
	ASPAMD_ERR_IF (err == -1, ASPAMD_ERR_NET,
		       "server %p: failed to start socket %i listening: %s",
		       server, server->socket, strerror (errno));

	server_fcntl (server->socket, O_NONBLOCK);
	ASPAMD_ERR_CHECK (ret);

	ret = aspamd_reactor_add (server->reactor, server->socket, POLLIN | POLLERR,
				  server);
	ASPAMD_ERR_CHECK (ret);
	ret = aspamd_reactor_on_io (server->reactor, server->socket,
				    (aspamd_reactor_cbck_t)&server_accept, 0);
	ASPAMD_ERR_CHECK (ret);
	ret = aspamd_reactor_on_idle (server->reactor, server->socket,
				      (aspamd_reactor_cbck_t)&server_idle, 0);
	ASPAMD_ERR_CHECK (ret);

	server->stub = stub;
	server->timeout = timeout;
	server->accepted = 0;
	server->timestamp = (gint) time (NULL);
	server->errors = 0;
	server->bytes_written = NULL;
	server->bytes_read = NULL;

	g_debug ("server %p: is started, stub mode - %i", server, stub);

at_exit:
	g_mutex_unlock (server->lock);
	return ret;
}

/** @brief detaches session
 *
 * @param server server data
 * @param session session to be closed
 */

void aspamd_server_detach (aspamd_server_t *server, aspamd_session_t *session)
{
	g_assert (server && session);

	g_mutex_lock (server->lock);
	if (g_slist_find (server->sessions, session))
	{
		if (g_slist_length (server->bytes_read) < ASPAMD_STAT_ENTRIES &&
		    g_slist_length (server->bytes_written) < ASPAMD_STAT_ENTRIES)
		{
			server->bytes_read = g_slist_append (
				server->bytes_read,
				(gpointer) session->bytes_read);
			server->bytes_written = g_slist_append (
				server->bytes_written,
				(gpointer) session->bytes_written);
		}
		else
		{
			g_debug ("server %p: no place to store stats, forcing dump", server);
			server_dump_stats (server);
		}
		server->sessions = g_slist_remove (server->sessions, session);
		server->garbage = g_slist_append (server->garbage, session);
		g_debug ("server %p: session %p is marked for removal",
			 server, session);
	}
	g_mutex_unlock (server->lock);
}

/** @brief stops server
 *
 * kills all running sessions and closes server socket
 *
 * @param server server data
 * @return an error code
 */

gint aspamd_server_stop (aspamd_server_t *server)
{
	gint ret = ASPAMD_ERR_OK;
	GSList	*iter = NULL;

	g_assert (server);

	g_mutex_lock (server->lock);
	if (server->socket > 0)
	{
		aspamd_reactor_remove (server->reactor, server->socket, server);
		if(shutdown (server->socket, SHUT_RDWR) == -1)
		{
			g_warning ("server %p: failed to shutdown socket %i: %s", server,
				   server->socket, strerror (errno));
			ret = ASPAMD_ERR_NET;
		}
		else
			g_debug ("server %p: socket %i is shut down", server, server->socket);
		close (server->socket);
		server->socket = 0;
	}
	if (server->type == ASPAMD_SERVER_UNIX)
		unlink (server->sock_path);
	if (server->sessions)
	{
		for (iter = server->sessions; iter; iter = g_slist_next (iter))
		{
			aspamd_session_stop (iter->data);
			server->garbage = g_slist_append (server->garbage, iter->data);
		}
		g_slist_free (server->sessions);
		server->sessions = NULL;
	}
	if (server->sessions_to_free)
	{
		for (iter = server->sessions_to_free; iter; iter = g_slist_next (iter))
			session_free (iter->data);
		g_slist_free (server->sessions_to_free);
		server->sessions_to_free = NULL;
	}
	server_dump_stats (server);
	g_mutex_unlock (server->lock);
	return ret;
}

/** @brief releases resources allocated by server
 *
 * @param server server to be released
 * @return an error code
 */

void aspamd_server_free (aspamd_server_t *server)
{
	GSList	*iter = NULL;

	g_assert (server);

	g_debug ("server at %p is about to be released", server);

	if (server->ip && server->ip != default_server_ip)
	{
		g_free (server->ip);
		server->ip = NULL;
	}
	
	if (server->sock_path && server->sock_path != default_socket_path)
	{
		g_free (server->sock_path);
		server->sock_path = NULL;
	}

	if (server->sessions)
	{
		for (iter = server->sessions; iter; iter = g_slist_next (iter))
			aspamd_session_unref (iter->data);
		g_slist_free (server->sessions);
		server->sessions = NULL;
	}

	if (server->sessions_to_free)
	{
		for (iter = server->sessions_to_free; iter; iter = g_slist_next (iter))
			session_free (iter->data);
		g_slist_free (server->sessions_to_free);
		server->sessions_to_free = NULL;
	}

	if (server->garbage)
	{
		for (iter = server->garbage; iter; iter = g_slist_next (iter))
			aspamd_session_unref (iter->data);
		g_slist_free (server->garbage);
		server->garbage = NULL;
	}

	if (server->lock)
	{
		g_free (server->lock);
		server->lock = NULL;
	}

	g_slice_free1 (sizeof (aspamd_server_t), server);
}

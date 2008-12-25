/* 
 * aspamd - advanced spam daemon 
 *
 */

/*! \file net.h
 *  \brief server and session strcutures definition */

#ifndef _ASPAMD_NET_
#define _ASPAMD_NET_

#include <poll.h>
#include <assassin.h>

#define ASPAMD_NET_MAX_CON			(256)
#define ASPAMD_NET_POLL_TIMEOUT			(512)

/** structure to keep client session data */
struct aspamd_session
{
	gint state;
	/*!< state of the session */
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
	struct assassin_parser *parser;
	/*!< parser to parse incoming data */
	gint head_allocated;
	/*!< buffer is allocated by g_slice_new routine */
};

typedef struct aspamd_session aspamd_session_t;

/** structure to keep server data */
struct aspamd_server
{
	gchar *ip;
	/*!< IPv4 address to bind to. allocated and released by
	 * configuration file parsing routine */
	gint port;
	/*!< TCP port to be used. initialized by configuration file
	 * parsing routine*/
	int socket;
	/*!< server socket file desciptor */
	struct pollfd *poll_fds;
	/*!< array of pollfd structures to be passed into poll
	 * function */
	gint num_fds;
	/*!< number of active file desciptors in the poll_fds array */
	GHashTable *sessions_by_fd;
	/*!< hash to store opened sessions. elements accessed via
	 * poll_fd->fd value */
	gint running;
	/*!< flag describing state of the network server. value that
	 * diffres from zero means that server is activer and running
	 * at the moment*/
};

typedef struct aspamd_server aspamd_server_t;

#endif

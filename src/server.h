/* 
 * aspamd - advanced spam daemon 
 *
 *
 */

/*! \file server.h
 *  \brief network server*/

#ifndef _ASPAMD_SERVER_
#define _ASPAMD_SERVER_

#include <kas.h>
#include <reactor.h>
#include <pairs.h>

enum aspamd_server_type
{
	ASPAMD_SERVER_INET,
	ASPAMD_SERVER_UNIX
};

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
	GMutex *lock;
	/*!< lock to protect sessions_by_fd and poll_fds */
	struct kas_data *kas;
	/*!< KAS wrapper to pass messages to */
	GSList *sessions;
	GSList *sessions_to_free;
	GSList *garbage;
	gint stub;
	/*!< do not pass data to the KAS engine, just send fake reply
	 * and close session */
	aspamd_reactor_t *reactor;
	gint timeout;
	/*!< read timeout */
	gint type;
	gchar *sock_path;
	gint accepted, errors;
	GSList *bytes_read, *bytes_written;
	gint timestamp;
};

typedef struct aspamd_server aspamd_server_t;

gint aspamd_server_allocate (aspamd_server_t **new_server, aspamd_reactor_t *reactor,
			     kas_data_t *kas);
gint aspamd_server_start (aspamd_server_t *server, gint type, gint stub, gint timeout);
void aspamd_server_detach (aspamd_server_t *server, aspamd_session_t *session);
gint aspamd_server_stop (aspamd_server_t *server);
void aspamd_server_free (aspamd_server_t *server);

extern aspamd_pair_t server_types[];

#endif


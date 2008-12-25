/* 
 * aspamd - advanced spam daemon
 *
 */

#ifndef _ASPAMD_REACTOR_
#define _ASPAMD_REACTOR_

#include <poll.h>

enum 
{
	ASPAMD_REACTOR_OK,
	ASPAMD_REACTOR_FINISHED,
	ASPAMD_REACTOR_ERR
};

enum 
{
	ASPAMD_REACTOR_INIT,
	ASPAMD_REACTOR_RUNNING,
	ASPAMD_REACTOR_STOPPING,
	ASPAMD_REACTOR_STOPPED,
	ASPAMD_REACTOR_ERROR
};

struct aspamd_reactor
{
	struct pollfd *poll_fds;
	/*!< array of pollfd structures to be passed into poll
	 * function */
	gint num_fds;
	/*!< maximum numbers of fds to be served */
	gint active_fds;
	/*!< number of active file desciptors in the poll_fds array */
	GHashTable *handlers;
	/*!< hash to store handlers */
	GMutex *lock;
	/*!< lock to protect handlers and poll_fds */
	gint state;
	gboolean rebuild;
	GSList *stale, *new;
};

typedef volatile struct aspamd_reactor aspamd_reactor_t;

struct aspamd_reactor_io
{
	gint events, mask;
};
typedef struct aspamd_reactor_io aspamd_reactor_io_t;

typedef gint (*aspamd_reactor_cbck_t) (gpointer data, gint fd, gpointer param);

gint aspamd_reactor_allocate (aspamd_reactor_t **new_reactor, gint num_fds);
gint aspamd_reactor_add (aspamd_reactor_t *reactor, gint fd, gint mask, gpointer data);
gint aspamd_reactor_on_colse (aspamd_reactor_t *reactor, gint fd,
			      aspamd_reactor_cbck_t cb, gint param);
gint aspamd_reactor_on_idle (aspamd_reactor_t *reactor, gint fd,
			     aspamd_reactor_cbck_t cb, gint param);
gint aspamd_reactor_on_io (aspamd_reactor_t *reactor, gint fd,
			   aspamd_reactor_cbck_t cb, gint param);
gint aspamd_reactor_remove (aspamd_reactor_t *reactor, gint fd, gpointer data);
gint aspamd_reactor_run (aspamd_reactor_t *reactor);
void aspamd_reactor_stop (aspamd_reactor_t *reactor);
void aspamd_reactor_wait (aspamd_reactor_t *reactor);
void aspamd_reactor_free (aspamd_reactor_t *reactor);

#endif

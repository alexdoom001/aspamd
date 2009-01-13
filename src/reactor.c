/* 
 * aspamd - advanced spam daemon
 *
 */

#include <string.h>
#include <errno.h>
#include <errors.h>
#include <glib.h>
#include <reactor.h>
#include <pairs.h>
#include <time.h>
#include <config.h>

enum 
{
	REACTOR_CB_IO,
	REACTOR_CB_IDLE,
	REACTOR_CB_CLOSE,
};

aspamd_pair_t cbs[] = {
	{REACTOR_CB_IO, "IO"},
	{REACTOR_CB_IDLE, "idle"},
	{REACTOR_CB_CLOSE, "close"}
};

struct reactor_handler
{
	gpointer data;
	aspamd_reactor_cbck_t io, idle, close;
	gint fd, mask;
	struct pollfd *poll_fd;
	gint state;
	gint timeout;
	time_t timestamp;
};

typedef volatile struct reactor_handler reactor_handler_t;

enum
{
	handler_state_unlinked,
	handler_state_linked,
	handler_state_stale,
	handler_state_reused
};

static void populate_poll_fd(aspamd_reactor_t *reactor, reactor_handler_t *handler)
{
	handler->poll_fd->fd = handler->fd;
	handler->poll_fd->events = handler->mask;
	handler->poll_fd->revents = 0;
	g_debug ("reactor %p: fd %i is added, mask - 0%o, "
		 "associated data - %p", reactor,
		 handler->fd, handler->mask, handler->data);
	handler->state = handler_state_linked;
}

static gint reactor_rebuild_poll (aspamd_reactor_t *reactor)
{
	gint ret = ASPAMD_ERR_OK;
	struct pollfd *fds = NULL;
	reactor_handler_t *handler = NULL;
	gint i, j;
	GSList *iter = NULL;
	int stale_length = 0;

	g_assert (reactor);

	if (!reactor->rebuild)
		return ret;

	if (reactor->stale)
	{
		stale_length = g_slist_length (reactor->stale);
		for (iter = reactor->stale; iter; iter = g_slist_next (iter))
		{
			handler = iter->data;
			g_assert (handler->poll_fd);
			handler->poll_fd->fd = 0;
			handler->poll_fd->events = 0;
			handler->poll_fd->revents = 0;
			if (handler->state == handler_state_stale)
			{
				g_debug ("reactor %p: fd %i is removed", reactor, 
					 handler->fd);
				g_assert (g_hash_table_remove (reactor->handlers,
							       (gpointer) handler->fd));
			}
		}
		g_slist_free (reactor->stale);
		reactor->stale = NULL;
	}

	fds = reactor->poll_fds;

	for (i = 0; i < reactor->active_fds; i++)
	{
		if (fds[i].fd > 0)
			continue;
		
		if (reactor->new)
		{
			handler = reactor->new->data;
			g_assert (handler);
			reactor->new = g_slist_remove (reactor->new,
						       (gconstpointer) handler);
			handler->poll_fd = &fds[i];
			populate_poll_fd (reactor, handler);
			stale_length --;
		}
		else
		{
			for (j = reactor->active_fds - 1; j > i ; j--)
			{
				if (fds[j].fd)
				{
					fds[i] = fds[j];
					handler = g_hash_table_lookup (
						reactor->handlers,
						(gpointer) fds[j].fd);
					g_assert (handler);
					handler->poll_fd = &fds[i];
					fds[j].fd = 0;
					break;
				}
			}
				
		}
	}
	if (stale_length)
		reactor->active_fds -= stale_length;

	if (reactor->active_fds > 0)
	{
		g_assert (reactor->poll_fds[reactor->active_fds - 1].fd);
		if (reactor->active_fds < reactor->num_fds)
			g_assert (!reactor->poll_fds[reactor->active_fds].fd);
	}

	if (reactor->new)
	{
		for (iter = reactor->new; iter; iter = g_slist_next (iter))
		{
			handler = iter->data;
			g_assert (handler);
			g_assert (reactor->active_fds < reactor->num_fds);
			handler->poll_fd = &fds[reactor->active_fds++];
			populate_poll_fd (reactor, handler);
		}
		g_slist_free (reactor->new);
		reactor->new = NULL;
	}

	if (reactor->active_fds > 0)
	{
		g_assert (reactor->poll_fds[reactor->active_fds - 1].fd);
		if (reactor->active_fds < reactor->num_fds)
			g_assert (!reactor->poll_fds[reactor->active_fds].fd);
	}

	reactor->rebuild = 0;
	return ret;
}

static void reactor_handler_destroy (gpointer data)
{
	g_slice_free1 (sizeof (reactor_handler_t), data);
}

static gint reactor_invoke_callback (aspamd_reactor_t *reactor, gint type, gint param)
{
	gint ret = ASPAMD_ERR_OK;
	gint i, handler_ret, param_internal;
	reactor_handler_t *handler = NULL;
	aspamd_reactor_io_t io_param;
	struct pollfd *fds = NULL;
	time_t timestamp;
	gint idle, timeout;

	g_assert (reactor);

	fds = reactor->poll_fds;

	timestamp = time (NULL);

	for (i = 0; i < reactor->active_fds; i++)
	{
		if (fds[i].fd > 0)
		{
			handler = g_hash_table_lookup (reactor->handlers,
						       (gpointer)fds[i].fd);
			g_assert (handler);
			g_assert (handler->fd == fds[i].fd);
			g_assert (handler->poll_fd == &fds[i]);
			if (handler->state != handler_state_linked)
				continue;
			else
			{
				io_param.events = fds[i].revents;
				io_param.mask = fds[i].events;
				handler_ret = -1;
				timeout = handler->timeout;
				idle = 0;
			}
		}
		else
			continue;

		g_mutex_unlock (reactor->lock);
		switch (type)
		{
		case REACTOR_CB_IO:
			if (io_param.events)
			{
				if (handler->io)
				{
					g_debug ("reactor %p: IO on fd - %i, events - 0%o",
						 reactor, fds[i].fd, io_param.events);
					handler_ret = handler->io (handler->data, fds[i].fd,
								   (gpointer)&io_param);
				}
				break;
			}
			/* else fallthrough as if idle */
		case REACTOR_CB_IDLE:
			if (handler->idle &&
			    handler->timeout >= 0 &&
			    (timestamp - handler->timestamp) > handler->timeout) {
				idle = 1;
				handler_ret = handler->idle(handler->data, fds[i].fd,
							    &timeout);
			} else
				idle = 0;
			break;
		case REACTOR_CB_CLOSE:
			if (handler->close)
			{
				param_internal = 0;
				g_debug ("reactor %p: close event is sent to fd %i",
					 reactor, fds[i].fd);
				handler_ret = handler->close (handler->data, fds[i].fd,
							      &param_internal);
			}
			break;
		}
		g_mutex_lock (reactor->lock);

		switch (handler_ret)
		{
		case ASPAMD_REACTOR_OK:
		{
			if (handler->state == handler_state_linked)
			{
				switch (type)
				{
				case REACTOR_CB_IO:
					if (fds[i].events != io_param.mask)
					{
						fds[i].events = io_param.mask;
						g_debug ("reactor %p: fd %i set new event "
							 "mask 0%o", reactor, fds[i].fd,
							 io_param.events);
					}
					/* break; */
				case REACTOR_CB_IDLE:
					if (idle)
					{
						handler->timestamp = timestamp;   
						if(handler->timeout != timeout)
						{
							handler->timeout = timeout;
							g_debug ("reactor %p: fd %i timeout "
								 "is changed to %i", reactor,
								 fds[i].fd, timeout);
						}
					}
					break;
				}
			}
			break;
		}
		case ASPAMD_REACTOR_FINISHED:
		case ASPAMD_REACTOR_ERR:
			if (handler->state != handler_state_stale)
			{
				g_debug ("reactor %p: fd %i is marked for removal",
					 reactor, fds[i].fd);
				reactor->stale = g_slist_append (reactor->stale,
								 (gpointer) handler);
				handler->state = handler_state_stale;
				reactor->rebuild = 1;
			}
		}
	}
	return ret;
}

gint reactor_set_handler (aspamd_reactor_t *reactor, gint fd, gint type,
			  aspamd_reactor_cbck_t cb, gint param)
{
	gint ret = ASPAMD_ERR_OK;
	reactor_handler_t *handler;
	aspamd_pair_t *pair = NULL;

	g_assert (reactor);

	g_mutex_lock (reactor->lock);
	handler = g_hash_table_lookup (reactor->handlers, (gpointer) fd);
	if (handler)
	{
		if (handler->state != handler_state_stale)
		{
			switch (type)
			{
			case REACTOR_CB_IO:
				handler->io = cb;
				if (param)
					handler->mask = (gint)param;
				break;
			case REACTOR_CB_IDLE:
				handler->idle = cb;
				handler->timestamp = time (NULL);
				handler->timeout = (gint)param;
				break;
			case REACTOR_CB_CLOSE:
				handler->close = cb;
				break;
			}
			pair = code_to_str (cbs, type);
			g_debug ("reactor %p: fd %i %s handler is set to %p",
				 reactor, fd, pair->string, cb);
		}
	}
	else
		ASPAMD_ERR (ASPAMD_ERR_PARAM, 
			    "reactor %p: failed to change callback of fd %i: "
			    "one is not added", reactor, fd);
at_exit:
	g_mutex_unlock (reactor->lock);
	return ret;
}

/*-----------------------------------------------------------------------------*/

gint aspamd_reactor_allocate (aspamd_reactor_t **new_reactor, gint num_fds)
{
	gint ret = ASPAMD_ERR_OK;
	aspamd_reactor_t *reactor = NULL;

	g_assert (num_fds > 0);

	reactor = g_slice_new (aspamd_reactor_t);
	ASPAMD_ERR_IF (!reactor, ASPAMD_ERR_MEM, "failed to allocate new poll reactor");
	reactor->state = ASPAMD_REACTOR_INIT;

	reactor->poll_fds = g_malloc0 (sizeof (struct pollfd) * num_fds);
	ASPAMD_ERR_IF (!reactor->poll_fds, ASPAMD_ERR_MEM,
		       "reactor %p: failed to allocated a polling array", reactor);
	reactor->num_fds = num_fds;
	reactor->active_fds = 0;
	reactor->rebuild = 0;
	reactor->stale = NULL;
	reactor->new = NULL;

	reactor->lock = g_mutex_new ();
	ASPAMD_ERR_IF (!reactor->lock, ASPAMD_ERR_MEM,
		       "reactor %p: failed to allocate a mutex", reactor);

	reactor->handlers =  g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL,
						    reactor_handler_destroy);
	ASPAMD_ERR_IF (!reactor->handlers, ASPAMD_ERR_MEM,
		       "reactor %p: failed to allocate a hash table", reactor);

	g_debug ("reactor at %p is allocated: maximum number of descriptors - %i",
		 reactor, reactor->num_fds);
	
at_exit:
	if (ret == ASPAMD_ERR_OK)
		*new_reactor = reactor;
	else
	{
		*new_reactor = NULL;
		aspamd_reactor_free (reactor);
	}
	return ret;
}

gint aspamd_reactor_add (aspamd_reactor_t *reactor, gint fd, gint mask, gpointer data)
{
	gint ret = ASPAMD_ERR_OK;
	reactor_handler_t *handler = NULL;
	gint unlinked = 0, stale = 0;;

	g_assert (reactor);

	g_mutex_lock (reactor->lock);
	if (reactor->new)
		unlinked = g_slist_length (reactor->new);
	if (reactor->stale)
		stale = g_slist_length (reactor->stale);

	ASPAMD_ERR_IF (reactor->active_fds + unlinked - stale >= reactor->num_fds,
		       ASPAMD_ERR_IO,
		       "reactor %p: maximum number of fd is achieved", reactor);

	handler = g_hash_table_lookup (reactor->handlers, (gpointer) fd);
	if (handler)
	{
		if (handler->state == handler_state_stale)
		{
			handler->state = handler_state_reused;
			reactor->stale = g_slist_append (reactor->stale, (gpointer) handler);
		}
		else
			ASPAMD_ERR (ASPAMD_ERR_PARAM,
				   "reactor %p: failed to add fd %i: one is already "
				   "added", reactor, fd);
	}
	else
	{
		handler = g_slice_new (reactor_handler_t);
		ASPAMD_ERR_IF (!handler, ASPAMD_ERR_MEM,
			       "reactor %p: failed to allocate handler", reactor);
		handler->state = handler_state_unlinked;
		g_hash_table_insert (reactor->handlers, (gpointer)fd,
				     (gpointer) handler);
	}
	handler->data = data;
	handler->io = NULL;
	handler->idle = NULL;
	handler->close = NULL;
	handler->fd = fd;
	handler->mask = mask;
	handler->timeout = -1;
	handler->timestamp = 0;
	reactor->new = g_slist_append (reactor->new, (gpointer)handler);
	reactor->rebuild = 1;
	g_debug ("reactor %p: new fd %i is en-queued", reactor, fd);
at_exit:
	g_mutex_unlock (reactor->lock);
	if (ret != ASPAMD_ERR_OK)
	{
		if (handler)
			g_slice_free1 (sizeof (reactor_handler_t), (gpointer) handler);
	}
	return ret;
}

gint aspamd_reactor_on_io (aspamd_reactor_t *reactor, gint fd,
			   aspamd_reactor_cbck_t cb, gint param)
{
	return reactor_set_handler (reactor, fd, REACTOR_CB_IO, cb, param);
}

gint aspamd_reactor_on_idle (aspamd_reactor_t *reactor, gint fd,
			     aspamd_reactor_cbck_t cb, gint param)
{
	return reactor_set_handler (reactor, fd, REACTOR_CB_IDLE, cb, param);
}

gint aspamd_reactor_on_colse (aspamd_reactor_t *reactor, gint fd,
			      aspamd_reactor_cbck_t cb, gint param)
{
	return reactor_set_handler (reactor, fd, REACTOR_CB_CLOSE, cb, param);
}

gint aspamd_reactor_remove (aspamd_reactor_t *reactor, gint fd, gpointer data)
{
	gint ret = ASPAMD_ERR_OK;
	reactor_handler_t *handler = NULL;

	g_assert (reactor);

	g_mutex_lock (reactor->lock);
	handler = g_hash_table_lookup (reactor->handlers, (gpointer) fd);
	if (handler)
	{
		ASPAMD_ERR_IF (handler->data != data, ASPAMD_ERR_PARAM,
			       "reactor %p: fd %i associated data does not match",
			       reactor, fd);
		if (handler->state != handler_state_stale)
		{
			handler->state = handler_state_stale;
			reactor->stale = g_slist_append (reactor->stale, (gpointer) handler);
			reactor->rebuild = 1;
			g_debug ("reactor %p: fd %i is marked for removal", reactor, fd);
		}
		else
			ret = ASPAMD_ERR_STATE;
	}
	else
	{
		g_warning ("reactor %p: failed to remove fd %i: one is not added",
			   reactor, fd);
		ret = ASPAMD_ERR_PARAM;
	}
at_exit:
	g_mutex_unlock (reactor->lock);
	return ret;
}

gint aspamd_reactor_run (aspamd_reactor_t *reactor)
{
	gint ret = ASPAMD_ERR_OK;
	int poll_ret = -1;

	g_assert (reactor);

	g_mutex_lock (reactor->lock);
	if (reactor->state == ASPAMD_REACTOR_INIT)
	{
		g_debug ("reactor %p: starting", reactor);
		reactor->state = ASPAMD_REACTOR_RUNNING;
	}
	else
		ASPAMD_ERR (ASPAMD_ERR_STATE,
			    "reactor %p: can not be started", reactor);
	while (reactor->state == ASPAMD_REACTOR_RUNNING)
	{
		reactor_rebuild_poll (reactor);
			
		g_mutex_unlock (reactor->lock);
		poll_ret = poll(reactor->poll_fds, reactor->active_fds,
				ASPAMD_REACTOR_TIMEOUT);
		g_mutex_lock (reactor->lock);

		if (poll_ret == -1)
		{
			reactor->state = ASPAMD_REACTOR_ERROR;
			ASPAMD_ERR (ASPAMD_ERR_IO, "reactor %p: polling error: %s",
				    reactor, strerror (errno));
		}
		else if (poll_ret == 0)
		{
			ret = reactor_invoke_callback (reactor, REACTOR_CB_IDLE, 0);
			ASPAMD_ERR_CHECK (ret);
		}
		else
		{
			ret = reactor_invoke_callback (reactor, REACTOR_CB_IO, 0);
			ASPAMD_ERR_CHECK (ret);
		}
	}
	if (reactor->state == ASPAMD_REACTOR_STOPPING)
	{
		g_debug ("reactor %p: stopping gracefully", reactor);
		reactor_invoke_callback (reactor, REACTOR_CB_CLOSE, 0);
		reactor->state = ASPAMD_REACTOR_STOPPED;
	}
at_exit:
	g_mutex_unlock (reactor->lock);
	return ret;
}

void aspamd_reactor_stop (aspamd_reactor_t *reactor)
{
	g_assert (reactor);

	g_debug ("reactor %p: stop is initiated", reactor);
	if (reactor->state == ASPAMD_REACTOR_RUNNING)
		reactor->state = ASPAMD_REACTOR_STOPPING;
}

void aspamd_reactor_wait (aspamd_reactor_t *reactor)
{
	g_assert (reactor);

	while (reactor->state != ASPAMD_REACTOR_INIT &&
	       reactor->state != ASPAMD_REACTOR_STOPPED);
	g_debug ("reactor %p: stopped", reactor);
}

void aspamd_reactor_free (aspamd_reactor_t *reactor)
{
	g_assert (reactor);

	if (reactor->state != ASPAMD_REACTOR_STOPPED)
	{
		aspamd_reactor_stop (reactor);
		aspamd_reactor_wait (reactor);
	}

	g_debug ("reactor %p is about to be released", reactor);

	if (reactor->new)
	{
		g_slist_free (reactor->new);
		reactor->new = NULL;
	}
	
	if (reactor->stale)
	{
		g_slist_free (reactor->stale);
		reactor->stale = NULL;
	}

	if (reactor->handlers)
	{
		g_hash_table_destroy (reactor->handlers);
		reactor->handlers = NULL;
	}

	if (reactor->poll_fds)
	{
		g_free ( reactor->poll_fds);
		reactor->poll_fds = NULL;
	}

	if (reactor->lock)
	{
		g_mutex_free (reactor->lock);
		reactor->lock = NULL;
	}

	g_slice_free1 (sizeof (aspamd_reactor_t), (gpointer) reactor);
}

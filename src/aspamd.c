/* 
 * aspamd - advanced spam daemon 
 *
 */

/*! \file aspamd.c
 *  \brief main module */

#include <sys/signalfd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include <errors.h>
#include <pairs.h>
#include <logging.h>
#include <reactor.h>
#include <server.h>
#include <kas.h>
#include <parser.h>
#include <aspamd.h>
#include <config.h>

static gint aspamd_setup_signalfd (aspamd_context_t *context);
static gint aspamd_check_signals (aspamd_context_t *context, gint fd,
				  aspamd_reactor_io_t *param);

aspamd_context_t context;

/** @brief initializes program context
 *
 * Initializes context by setting structure members to default values
 *
 * @param context a global context to be initialized
 */

gint aspamd_initialize_context(aspamd_context_t *context)
{
	gint ret = ASPAMD_ERR_OK;

	g_assert (context);

	memset (context, 0, sizeof (aspamd_context_t));
	context->timeout = ASPAMD_DEFAULT_TIMEOUT;

	ret = aspamd_logger_allocate (&context->log);
	ASPAMD_ERR_CHECK (ret);
	aspamd_logger_early_configure (context->log);
	ret = aspamd_reactor_allocate (&context->reactor, ASPAMD_NET_MAX_CON + 2);
	ASPAMD_ERR_CHECK (ret);
	ret = aspamd_kas_allocate (&context->kas);
	ASPAMD_ERR_CHECK (ret);
	ret = aspamd_server_allocate (&context->server, context->reactor, context->kas);
	ASPAMD_ERR_CHECK (ret);
	aspamd_setup_signalfd (context);
	ASPAMD_ERR_CHECK (ret);

at_exit:
	return ret;
}

/** @brief deinitializes program context
 *
 * Deinitializes context. All allocated memory will be released by
 * according functions like a g_free and etc.
 *
 * @param context a global context to be initialized
 */

void aspamd_deinitialize_context(aspamd_context_t *context)
{
	g_assert (context);

	if (context->config_path)
		g_free (context->config_path);
	if (context->pid_file_path)
		g_free (context->pid_file_path);
	/* this block should be on top or callback will be initiated
	 * for orphaned session */
	if (context->kas)
	{
		aspamd_kas_stop (context->kas);
		aspamd_kas_deinitialize (context->kas);
		aspamd_kas_free (context->kas);
	}
	if (context->server)
	{
		aspamd_server_stop (context->server);
		aspamd_server_free (context->server);
	}
	if (context->reactor)
		aspamd_reactor_free (context->reactor);
	if (context->log)
		aspamd_logger_free (context->log);
	if (context->signal_fd)
	{
		close (context->signal_fd);
		context->signal_fd = -1;
	}
}

/** @brief parses command line
 *
 * parses command line using glib utilities. mandatory parameters
 * presence is checked.
 *
 * @param context a global context
 * @param argc parameters count
 * @param argv array of strings 
 * @return an error code
 */

gint aspamd_parse_com_line (aspamd_context_t *context, int argc, char *argv[])
{
	gint ret = ASPAMD_ERR_OK;
	GError *gerr = NULL;
	GOptionContext *opt_context = NULL;

	g_assert (context);

	GOptionEntry entries[] = 
		{
			{ "config", 'c', 0, G_OPTION_ARG_STRING,
			  &context->config_path,
			  "path to configuration file", NULL},
			{ "daemonize", 'd', 0, G_OPTION_ARG_NONE,
			  &context->daemonize,
			  "detach from console and run as daemon", NULL},
			{ "stub", 's', 0, G_OPTION_ARG_NONE,
			  &context->stub,
			  "detach from console and run as daemon", NULL},
			{ "license-info", 'l', 0, G_OPTION_ARG_NONE,
			  &context->print_license_info,
			  "print license information and exit", NULL},
			{ NULL }
		};

	opt_context = g_option_context_new ("- advanced spam filtering daemon");
	ASPAMD_ERR_IF (!opt_context, ASPAMD_ERR_MEM, "memory allocation failed");
	g_option_context_add_main_entries (opt_context, entries, NULL);
	ASPAMD_ERR_IF ( !g_option_context_parse (opt_context, &argc, &argv, &gerr),
		ASPAMD_ERR_CM_LINE, "option parsing failed: %s", gerr->message);
	g_debug ("command line parsed successfully");
	ASPAMD_ERR_IF (!context->config_path, ASPAMD_ERR_CM_LINE,
		       "config file name is missing");
at_exit:
	if (gerr)
		g_error_free (gerr);
	if (opt_context)
		g_option_context_free (opt_context);
	return ret;
}

static void file_get_string(GKeyFile *key_file, const gchar *group_name, const gchar *key,
			gchar **config_val, int warning)
{
	GError *gerr = NULL;
	gchar *str_value = NULL;
	str_value = g_key_file_get_string (key_file, group_name, key, &gerr);
	if (gerr)
	{
		if (gerr->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND && warning)
			g_warning ("%s::%s read failed: %s", group_name, key, gerr->message);
		g_error_free (gerr);
	}
	if (str_value)
	{
		*config_val = g_strchomp (str_value);
		g_message ("%s::%s is set to: %s", group_name, key, *config_val);
	}
}

static void file_get_integer(GKeyFile *key_file, const gchar *group_name, const gchar *key,
		gint *config_val, int warning)
{
	GError *gerr = NULL;
	gint int_value = -1;
	int_value = g_key_file_get_integer (key_file, group_name, key, &gerr);
	if (gerr)
	{
		if (gerr->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND && warning)
			g_warning ("%s::%s read failed: %s", group_name, key, gerr->message);
		g_error_free (gerr);
	}
	if (int_value)
	{
		*config_val = int_value;
		g_message ("%s::%s is set to: %d", group_name, key, *config_val);
	}
}

/** @brief loads config file
 *
 * loads parameters from config file using glib utilities. missed or
 * malformed parameters are suppressed by default values.
 *
 * @param context a global context
 * @return an error code
 */

gint aspamd_load_config (aspamd_context_t *context)
{
	gint ret = ASPAMD_ERR_OK;
	GError *gerr = NULL;
	GKeyFile *key_file = NULL;
	gchar *str_value = NULL;
	gint int_value = -1;
	GRegex *reg_ex = NULL;
	GMatchInfo *match_info = NULL;
	aspamd_pair_t *pair = NULL;

	g_assert (context);

	key_file = g_key_file_new ();
	ASPAMD_ERR_IF (!key_file, ASPAMD_ERR_MEM, "memory allocation failed");

	ASPAMD_ERR_IF (!g_key_file_load_from_file (key_file, context->config_path,
						   G_KEY_FILE_NONE, &gerr),
		       ASPAMD_ERR_CFG, "configuration file parsing failed: %s",
		       gerr->message);
	g_debug ("configuration file parsed successfully");

	file_get_string(key_file, "general", "pid_file", &context->pid_file_path, 1);

	str_value = g_key_file_get_string (key_file, "logging", "type", &gerr);
	if (gerr)
	{
		if (gerr->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND)
			g_warning ("logging::type read failed: %s",
				   gerr->message);
		g_error_free (gerr);
		gerr = NULL;
	}

	if (str_value)
	{
		str_value = g_strchomp (str_value);
		pair = str_to_code (logs, str_value);
		if (pair->code == -1)
			g_warning ("unknown logger type: %s", str_value);
		else
		{
			context->log->type = pair->code;
			g_message ("log type is set to: %s", pair->string);
		}
		g_free (str_value);
		str_value = NULL;
	}

	str_value = g_key_file_get_string (key_file, "logging", "level", &gerr);
	if (gerr)
	{
		if (gerr->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND)
			g_warning ("logging::level read failed: %s",
				   gerr->message);
		g_error_free (gerr);
		gerr = NULL;
	}

	if (str_value)
	{
		str_value = g_strchomp (str_value);
		if (g_ascii_strcasecmp (str_value, "error") == 0)
			context->log->level = G_LOG_LEVEL_ERROR;
		else if (g_ascii_strcasecmp (str_value, "critical") == 0)
			context->log->level = G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_ERROR;
		else if (g_ascii_strcasecmp (str_value, "warning") == 0)
			context->log->level = G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL
				| G_LOG_LEVEL_ERROR;
		else if (g_ascii_strcasecmp (str_value, "message") == 0)
			context->log->level = G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_WARNING
				| G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_ERROR;
		else if (g_ascii_strcasecmp (str_value, "info") == 0)
			context->log->level = G_LOG_LEVEL_INFO | G_LOG_LEVEL_MESSAGE
				| G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL
				| G_LOG_LEVEL_ERROR;
		else if (g_ascii_strcasecmp (str_value, "debug") == 0)
			context->log->level = G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_INFO
				| G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_WARNING
				| G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_ERROR;
		else
			g_warning ("unknown log level: %s", str_value);
		g_message ("log level is set to: %s", aspamd_log_level_to_str (
				   context->log->level));
		g_free (str_value);
		str_value = NULL;
	}

	if (context->log->type == aspamd_log_file)
	{
		file_get_string(key_file, "logging", "path", &context->log->path, 1);

		int_value = g_key_file_get_boolean (key_file, "logging", "overwrite", &gerr);
		if (gerr)
		{
			if (gerr->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND)
				g_warning ("logging::overwrite read failed: %s",
					   gerr->message);
			g_error_free (gerr);
			gerr = NULL;
		}

		if (int_value)
		{
			context->log->file_overwrite = int_value;
			g_message ("logger file overwrite mode is set to: %i", int_value);
			int_value = 0;
		}
	}
	if (context->log->type == aspamd_log_file ||
	    context->log->type == aspamd_log_console)
	{
		str_value = g_key_file_get_string (key_file, "logging", "timestamp", &gerr);
		if (gerr)
		{
			if (gerr->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND)
				g_warning ("logging::timestamp read failed: %s",
					   gerr->message);
			g_error_free (gerr);
			gerr = NULL;
		}

		if (str_value)
		{
			str_value = g_strchomp (str_value);
			pair = str_to_code (log_stamps, str_value);
			if (pair->code == -1)
				g_warning ("unknown timestamp format: %s", str_value);
			else
			{
				context->log->file_tstamp = pair->code;
				g_message ("logger time stamp format is set to: %s",
					pair->string);
			}
			g_free (str_value);
			str_value = NULL;
		}
	}

	str_value = g_key_file_get_string (key_file, "net", "socket", &gerr);
	if (gerr)
	{
		if (gerr->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND)
			g_warning ("net::socket read failed: %s",
				   gerr->message);
		g_error_free (gerr);
		gerr = NULL;
	}

	if (str_value)
	{
		str_value = g_strchomp (str_value);
		pair = str_to_code (server_types, str_value);

		if (pair->code == -1)
		{
			g_warning ("malformed socket type: %s", str_value);
			context->server_type = ASPAMD_SERVER_INET;
		}
		else
		{
			g_message ("net::socket is set to: %s", pair->string);
			context->server_type = pair->code;
		}
		g_free (str_value);
		str_value = NULL;
	}

	if (context->server_type == ASPAMD_SERVER_INET)
	{
		str_value = g_key_file_get_string (key_file, "net", "ip", &gerr);
		if (gerr)
		{
			if (gerr->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND)
				g_warning ("net::ip read failed: %s",
					   gerr->message);
			g_error_free (gerr);
			gerr = NULL;
		}

		if (str_value)
		{
			str_value = g_strchomp (str_value);
			reg_ex =  g_regex_new ("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$",
					       G_REGEX_OPTIMIZE,
					       G_REGEX_MATCH_ANCHORED,
					       &gerr);
			if (gerr)
			{
				g_critical ("regular expression error: %s", gerr->message);
				g_error_free (gerr);
			}
			else
			{
				if(g_regex_match (reg_ex, str_value, 0, &match_info))
				{
					g_message ("network ip address is set to: %s",
						   str_value);
					context->server->ip = str_value;
				}
				else
				{
					g_warning ("malformed IPv4 network address: %s",
						   str_value);
					g_free (str_value);
				}
				if (match_info)
				{
					g_match_info_free (match_info);
					match_info = NULL;
				}
				str_value = NULL;
			}
		}

		int_value = g_key_file_get_integer (key_file, "net", "port", &gerr);
		if (gerr)
		{
			if (gerr->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND)
				g_warning ("net::port read failed: %s", gerr->message);
			g_error_free (gerr);
			gerr = NULL;
		}

		if (int_value)
		{
			if (int_value & ~G_MAXUINT16)
				g_warning ("net::port value is to big");
			else
			{
				context->server->port = int_value;
				g_message ("network port is set to: %i",
					   context->server->port);
			}
			int_value = 0;
		}
	}
	else 
		file_get_string(key_file, "net", "path", &context->server->sock_path, 1);

	file_get_integer(key_file, "net", "timeout", &context->timeout, 1);

	file_get_string(key_file, "kas", "work_path", &context->kas->work_path, 1);
	file_get_string(key_file, "kas", "license_path", &context->kas->license_path, 1);
	file_get_string(key_file, "kas", "update_path", &context->kas->update_path, 1);
	file_get_integer(key_file, "kas", "queue_size", &context->kas->queue_size, 1);
	file_get_integer(key_file, "kas", "thread_count", &context->kas->threads_count, 1);
	file_get_integer(key_file, "kas", "use_uds", &context->kas->use_uds, 0);
	file_get_integer(key_file, "kas", "ext_net", &context->kas->ext_net, 0);
	file_get_integer(key_file, "kas", "parse_bin", &context->kas->parse_bin, 0);

	file_get_integer(key_file, "reputation_filtering", "enable", &context->kas->filtering.enable, 0);
	file_get_integer(key_file, "reputation_filtering", "storage_size", &context->kas->filtering.storage_size, 0);
	file_get_string(key_file, "reputation_filtering", "storage_path", &context->kas->filtering.storage_path, 0);

at_exit:
	if (gerr)
		g_error_free (gerr);
	if (str_value)
		g_free (str_value);
	if (key_file)
		g_key_file_free (key_file);
	if (match_info)
		g_match_info_free (match_info);
	if (reg_ex)
		g_regex_unref(reg_ex);

	return ret;
}

/** @brief make a process running in a background
 *
 * daemonizes process using well-known sequence of fork and setsid
 * calls.
 *
 * @param context a global context
 * @return an error code
 */

gint aspamd_daemonize (aspamd_context_t *context)
{
	gint ret = ASPAMD_ERR_OK;
	int ppid, pid, sid;

	g_assert (context);

	ppid = getppid ();

	ASPAMD_ERR_IF(ppid == 1, ASPAMD_ERR_OK,
		      "forked from init process, daemonization skipped");

	pid = fork();
	ASPAMD_ERR_IF (pid == -1, ASPAMD_ERR_DAEMONIZE, "fork failed: %s",
		       strerror (errno));
	if (pid > 0)
		exit(0);

	sid = setsid();
	ASPAMD_ERR_IF (sid == -1, ASPAMD_ERR_DAEMONIZE, 
		       "failed to become group leader: %s", strerror (errno));
	pid = getpid ();

	g_message ("daemonized successfully, pid - %i", pid);

	context->pid = pid;

at_exit:
	return ret;
}

gint aspamd_store_pid (aspamd_context_t *context)
{
	gint ret = ASPAMD_ERR_OK;
	FILE *file = NULL;

	g_assert (context);

	if (context->pid_file_path)
	{
		file = fopen (context->pid_file_path, "w");
		ASPAMD_ERR_IF (!file, ASPAMD_ERR_ERR, 
			       "failed to open pid file %s: %s", context->pid_file_path,
			       strerror (errno));
		fprintf (file, "%i", context->pid);
		g_debug ("pid file %s is updated", context->pid_file_path);
	}
at_exit:
	if (file)
		fclose (file);
	return ret;
}

static gint aspamd_check_signals (aspamd_context_t *context, gint fd,
				  aspamd_reactor_io_t *io)
{
	gint ret = ASPAMD_ERR_OK;
	struct signalfd_siginfo sig_info;
	gint bytes_read = 0;

	g_assert (context && io);

	bytes_read = read (fd, &sig_info, sizeof (struct signalfd_siginfo));
	if (bytes_read != sizeof (struct signalfd_siginfo))
	{
		if (errno != EAGAIN)
			g_warning ("failed to read signal data "
				   "from desciptor %i: %s",
				   fd, strerror (errno));
		goto at_exit;
	}

	switch (sig_info.ssi_signo)
	{
	case SIGINT:
	case SIGQUIT:
	case SIGTERM:
	{
		g_message ("terminating");
		aspamd_reactor_stop (context->reactor);
		break;
	}
	case SIGHUP:
		aspamd_kas_reload_database (context->kas);
		break;
	default:
		g_warning ("unexpected signal %i is received", sig_info.ssi_signo);
	}

at_exit:
	if (ret == ASPAMD_ERR_OK)
		return ASPAMD_REACTOR_OK;
	else
		return ASPAMD_REACTOR_ERR;
}

static gint aspamd_setup_signalfd (aspamd_context_t *context)
{
	gint ret = ASPAMD_ERR_OK;
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGHUP);

	context->signal_fd = signalfd (-1, &mask, SFD_NONBLOCK);
	ASPAMD_ERR_IF (context->signal_fd == -1, ASPAMD_ERR_IO,
		       "failed to create descriptor to handle signals: %s",
		       strerror (errno));
	g_debug ("signal descriptor %i is opened", context->signal_fd);

	ASPAMD_ERR_IF (sigprocmask(SIG_BLOCK, &mask, NULL) == -1,
		       ASPAMD_ERR_IO,"failed to block signals delivery: %s",
		       strerror (errno));

	ret = aspamd_reactor_add (context->reactor, context->signal_fd, POLL_IN, context);
	ASPAMD_ERR_CHECK (ret);
	ret = aspamd_reactor_on_io (context->reactor, context->signal_fd,
				    (aspamd_reactor_cbck_t) aspamd_check_signals, 0);
	ASPAMD_ERR_CHECK (ret);

at_exit:
	return ret;
}

int main (int argc, char *argv[])
{
	gint ret = ASPAMD_ERR_OK;
	static KasSdkLicenseInfo info;

	g_thread_init (NULL);

	ret = aspamd_initialize_context (&context);
	ASPAMD_ERR_CHECK (ret);
	ret = aspamd_parse_com_line (&context, argc, argv);
	ASPAMD_ERR_CHECK (ret);
	ret = aspamd_load_config (&context);
	ASPAMD_ERR_CHECK (ret);
	ret = aspamd_logger_configure (context.log);
	if (ret != ASPAMD_ERR_OK)
	{
		aspamd_logger_early_configure (context.log);
		g_critical ("logger reconfiguration failed");
	}
	g_message ("%s version: %s", PACKAGE, PACKAGE_VERSION);
	if (context.daemonize && ! context.print_license_info)
	{
		ret = aspamd_daemonize (&context);
		ASPAMD_ERR_CHECK (ret);
		ret = aspamd_store_pid (&context);
		ASPAMD_ERR_CHECK (ret);
	}

	if (!context.stub || context.print_license_info)
	{
		ret = aspamd_kas_initialize (context.kas);
		if (ret == ASPAMD_ERR_LIC_EXP)
			g_message ("KAS license expired");
		else
		{
			ASPAMD_ERR_CHECK (ret);
		}
	}

	if (context.print_license_info)
	{
		ret = aspamd_kas_get_license_info (&info);
		ASPAMD_ERR_CHECK (ret);
		g_message ("license - %s, expire - %u/%u/%u (m/d/y)",
			info.keyFileName, info.expirationDate.month,
			info.expirationDate.day, info.expirationDate.year);
		goto at_exit;
	}

	ret = aspamd_server_start (context.server, context.server_type,
				   context.stub, context.timeout);
	ASPAMD_ERR_CHECK (ret);

	ret = aspamd_reactor_run (context.reactor);
	ASPAMD_ERR_CHECK (ret);

at_exit:
	if (context.pid_file_path)
		unlink (context.pid_file_path);
	aspamd_deinitialize_context (&context);
	return ret;
}

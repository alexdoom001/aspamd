/* 
 * aspamd - advanced spam daemon 
 *
 */

/*! \file aspamd.c
 *  \brief main module */

#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include "errors.h"
#include "logging.h"
#include "server.h"
#include "aspamd.h"

static gchar *default_net_ip = ASPAMD_DEFAULT_NET_IP,
	*default_log_path = ASPAMD_DEFAULT_LOG_PATH;

aspamd_context_t context;

/** @brief initializes program context
 *
 * Initializes context by setting structure members to default values
 *
 * @param context a global context to be initialized
 */

void aspamd_initialize_context(aspamd_context_t *context)
{
	memset (context, 0, sizeof (aspamd_context_t));
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
	if (context->config_path)
		g_free (context->config_path);
	if (context->log.path && context->log.path != default_log_path)
		g_free (context->log.path);
	if (context->server.ip && context->server.ip != default_net_ip)
		g_free (context->server.ip);
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
	gint err = ASPAMD_ERR_OK;
	GError *gerr = NULL;
	GOptionContext *opt_context = NULL;

	GOptionEntry entries[] = 
		{
			{ "config", 'c', 0, G_OPTION_ARG_STRING,
			  &context->config_path,
			  "path to configuration file", NULL},
			{ "daemonize", 'd', 0, G_OPTION_ARG_NONE,
			  &context->daemonize,
			  "detach from console and run as daemon", NULL},
			{ NULL }
		};

	opt_context = g_option_context_new ("- advanced spam filtering daemon");
	if (!opt_context)
	{
		g_critical ("memory allocation failed");
		err = ASPAMD_ERR_MEM;
		goto at_exit;
	}
	g_option_context_add_main_entries (opt_context, entries, NULL);
	if (!g_option_context_parse (opt_context, &argc, &argv, &gerr))
	{                
		g_critical ("option parsing failed: %s", gerr->message);
		err = ASPAMD_ERR_CM_LINE;
		goto at_exit;
	}
	g_debug ("command line parsed successfully");
	if (!context->config_path)
	{
		g_critical ("config file name is missing");
		err = ASPAMD_ERR_CM_LINE;
		goto at_exit;
	}
at_exit:
	if (opt_context)
		g_option_context_free (opt_context);
	return err;
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
	gint err = ASPAMD_ERR_OK;
	GError *gerr = NULL;
	GKeyFile *key_file = NULL;
	gchar *log_type, *log_level;
	GRegex *reg_ex;
	GMatchInfo *match_info;

	key_file = g_key_file_new ();
	if (!key_file)
	{
		g_critical ("memory allocation failed");
		err = ASPAMD_ERR_MEM;
		goto at_exit;
	}
	if (! g_key_file_load_from_file (key_file, context->config_path,
					 G_KEY_FILE_NONE, &gerr))
	{
		g_critical ("configuration file parsing failed: %s", gerr->message);
		err = ASPAMD_ERR_CFG;
		goto at_exit;
	}
	g_debug ("configuration file parsed successfully");

	log_type = g_key_file_get_string (key_file, "logging", "type", &gerr);
	if (gerr)
		g_critical ("key read logging::type failed: %s", gerr->message);

	if (gerr || !log_type)
	{
		context->log.type = ASPAMD_DEFAULT_LOG_TYPE;
		g_warning ("resetting log type to default value");
	}
	else
	{
		if (strcmp (log_type, "syslog") == 0)
			context->log.type = aspamd_log_syslog;
		else if (strcmp (log_type, "file") == 0)
			context->log.type = aspamd_log_file;
		else if (strcmp (log_type, "console") == 0)
			context->log.type = aspamd_log_console;
		else
		{
			g_warning ("unknown logger type: %s", log_type);
			context->log.type = ASPAMD_DEFAULT_LOG_TYPE;
		}
	}
	g_free (log_type);
	g_message ("log type set to: %s", ASPAMD_LOGT_TO_STR (context->log.type));

	log_level = g_key_file_get_string (key_file, "logging", "level", &gerr);
	if (gerr)
		g_critical ("key read logging::level failed: %s", gerr->message);

	if (gerr || !log_level)
	{
		context->log.level = ASPAMD_DEFAULT_LOG_LEVEL;
		g_warning ("resetting log level to default value");
	}
	else
	{
		if (strcmp (log_level, "error") == 0)
			context->log.level = G_LOG_LEVEL_ERROR;
		else if (strcmp (log_level, "critical") == 0)
			context->log.level = G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_ERROR;
		else if (strcmp (log_level, "warning") == 0)
			context->log.level = G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL
				| G_LOG_LEVEL_ERROR;
		else if (strcmp (log_level, "message") == 0)
			context->log.level = G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_WARNING
				| G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_ERROR;
		else if (strcmp (log_level, "info") == 0)
			context->log.level = G_LOG_LEVEL_INFO | G_LOG_LEVEL_MESSAGE
				| G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL
				| G_LOG_LEVEL_ERROR;
		else if (strcmp (log_level, "debug") == 0)
			context->log.level = G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_INFO
				| G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_WARNING
				| G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_ERROR;
		else
		{
			g_warning ("unknown log level: %s", log_level);
			context->log.level = ASPAMD_DEFAULT_LOG_LEVEL;
		}
	}
	g_free (log_level);
	g_message ("log level set to: %s",
		   aspamd_log_level_to_str (context->log.level));

	if (context->log.type == aspamd_log_file)
	{
		context->log.path = g_key_file_get_string
			(key_file, "logging", "path", &gerr);
		if (gerr)
			g_critical ("key read logging::path failed: %s",
				 gerr->message);
		if (gerr || !context->log.path)
		{
			context->log.path = default_log_path;
			g_warning ("resetting log to default value");
		}
		g_message ("log set to: %s", context->log.path);
	}

	context->server.ip = g_key_file_get_string (key_file, "net", "ip", &gerr);
	if (gerr)
		g_critical ("key read net::ip failed: %s", gerr->message);
	if (gerr || ! context->server.ip)
	{
		context->server.ip = default_net_ip;
		g_warning ("resetting network ip address to default value");
	}
	else
	{
		reg_ex =  g_regex_new ("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$",
				       G_REGEX_OPTIMIZE,
				       G_REGEX_MATCH_ANCHORED,
				       &gerr);
		if (gerr)
		{
			g_critical ("regular expression error: %s", gerr->message);
			err = ASPAMD_ERR_ERR;
			goto at_exit;
		}
		if(!g_regex_match (reg_ex, context->server.ip, 0, &match_info))
		{
			g_warning ("malformed IPv4 network address: %s",
				context->server.ip);
			context->server.ip = default_net_ip;
		}
		if (match_info)
			g_match_info_free (match_info);
		
	}
	g_message ("network ip address set to: %s", context->server.ip);

	context->server.port = g_key_file_get_integer (key_file, "net", "port", &gerr);
	if (gerr)
		g_critical ("key read net::port failed: %s", gerr->message);
	if (gerr || ! context->server.port)
	{
		context->server.port = ASPAMD_DEFAULT_NET_PORT;
		g_warning ("resetting network port to default value");
	}
	g_message ("network port set to: %i", context->server.port);

at_exit:
	if (key_file)
		g_key_file_free (key_file);
	if (reg_ex)
		g_regex_unref(reg_ex);

	return err;
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
	int ppid, pid, sid;

	ppid = getppid ();

	if (ppid == 1)
	{
		g_debug ("forked from init process, daemonization skipped");
		return ASPAMD_ERR_OK;
	}

	pid = fork();
	if (pid == -1)
	{
		g_critical ("fork failed: %s", strerror (errno));
		return ASPAMD_ERR_DAEMONIZE;
	}
	else if (pid > 0)
		exit(0);

	sid = setsid();
	if (sid == -1) {
		g_critical ("failed to become group leader: %s", strerror (errno));
		return ASPAMD_ERR_DAEMONIZE;
	}
	pid = getpid ();

	g_debug ("daemonized successfully, pid - %i", pid);

	return ASPAMD_ERR_OK;
}

/** @brief signal handler
 *
 * handles received signals. if SIGTERM is received then global flag
 * will be set to terminate daemon execution gracefully. if SIGHUP is
 * received then configuration file will be reloaded and according
 * subsystems will be reconfigured.
 *
 * @param sig signal to be handled
 * @return an error code
 */

void aspamd_signal_handler (int sig)
{
	if (sig == SIGHUP)
	{
		g_message ("got SIGHUP");
		/* configuration reload should be added here */
	}
	else if (sig == SIGTERM)
	{
		g_message ("got SIGTERM, terminating server");
		context.server.running = 0;
	}
}

/** @brief setups signal handling
 *
 * set handlers for SIGTERM and SIGHUP signals
 *
 * @param context a global context
 * @return an error code
 */

gint aspamd_setup_sig_handler ()
{
	struct sigaction sig_action;

	sig_action.sa_handler = & aspamd_signal_handler;
	sig_action.sa_flags =  0;

	sigemptyset (&sig_action.sa_mask);
	sigaddset (&sig_action.sa_mask, SIGTERM);

	if(sigaction (SIGHUP, &sig_action, NULL) == -1)
	{
		g_critical ("failed to set signal handler");
		return ASPAMD_ERR_ERR;
	}

	sigemptyset (&sig_action.sa_mask);
	sigaddset (&sig_action.sa_mask, SIGHUP);

	if(sigaction (SIGTERM, &sig_action, NULL) == -1)
	{
		g_critical ("failed to set signal handler");
		return ASPAMD_ERR_ERR;
	}

	return ASPAMD_ERR_OK;
}

int main (int argc, char *argv[])
{
	gint ret = ASPAMD_ERR_OK;

	aspamd_initialize_context (&context);
	ret = aspamd_logger_early_configure (&context.log);
	ASPAMD_ERR_CHECK (ret);
	ret = aspamd_parse_com_line (&context, argc, argv);
	ASPAMD_ERR_CHECK (ret);
	ret = aspamd_load_config (&context);
	ASPAMD_ERR_CHECK (ret);
	ret = aspamd_logger_configure (&context.log);
	ASPAMD_ERR_CHECK (ret);
	if (context.daemonize)
	{
		ret = aspamd_daemonize (&context);
		ASPAMD_ERR_CHECK (ret);
	}
	ret = aspamd_start_server (&context.server);
	ASPAMD_ERR_CHECK (ret);

	ret = aspamd_setup_sig_handler ();
	ASPAMD_ERR_CHECK (ret);

	ret = aspamd_server_run (&context.server);
	ASPAMD_ERR_CHECK (ret);

at_exit:
	aspamd_stop_server (&context.server);
	aspamd_deinitialize_context (&context);
	return ret;
}

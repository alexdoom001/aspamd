/* 
 * aspamd - advanced spam daemon 
 *
 */

#include <string.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <glib.h>
#include <errors.h>
#include <logging.h>

gchar *aspamd_log_type_to_str[] = {
	"syslog",
	"file",
	"console"
};

const gchar *aspamd_log_level_to_str (GLogLevelFlags log_level)
{
	log_level &= G_LOG_LEVEL_MASK;

	if (log_level & G_LOG_LEVEL_DEBUG)
		return "DBG";
	else if (log_level & G_LOG_LEVEL_INFO)
		return "INF";
	else if (log_level & G_LOG_LEVEL_MESSAGE)
		return "MSG";
	else if (log_level & G_LOG_LEVEL_WARNING)
		return "WRN";
	else if (log_level & G_LOG_LEVEL_CRITICAL)
		return "CRT";
	else if (log_level & G_LOG_LEVEL_ERROR)
		return "ERR";
	else
		return "UNKNOWN";
}

static void aspamd_log_void_handler (const gchar *log_domain,
				      GLogLevelFlags  log_level,
				      const gchar *message, gpointer data)
{
}

/** @brief file/console backend
 *
 * extends message with time-stamp and log level information. formed
 * string will be written to file/console accordingly.
 *
 * @return an error code
 */

static void aspamd_log_stdio_handler (const gchar *log_domain,
				      GLogLevelFlags  log_level,
				      const gchar *message, gpointer data)
{
	aspamd_log_data_t *log = data;
	gchar buffer[ASPAMD_MAX_LINE_LEN];
	gint offset = 0, bytes_written;
	time_t tt;
	struct tm * tm;

	g_assert (log);

	time (&tt);
	tm = localtime (&tt);
	offset = snprintf (buffer, ASPAMD_MAX_LINE_LEN, "%i/%i/%i %i:%i %s[%s]: %s\n",
			   tm->tm_mday, tm->tm_mon + 1, 1900 + tm->tm_year,
			   tm->tm_hour, tm->tm_min, log_domain,
			   aspamd_log_level_to_str (log_level), message);
	bytes_written = fprintf (log->file, buffer);
	g_assert (bytes_written > 0);
}

/** @brief syslog backend
 *
 * writes message to the syslog without any prefixes and etc.
 *
 * @return an error code
 */

static void aspamd_log_syslog_handler (const gchar *log_domain,
				       GLogLevelFlags  log_level,
				       const gchar *message, gpointer log)
{
	int priority;

	g_assert (log);

	switch (log_level & G_LOG_LEVEL_MASK)
	{
	case G_LOG_LEVEL_ERROR:
		priority = LOG_ERR;
		break;
	case G_LOG_LEVEL_CRITICAL:
		priority = LOG_CRIT;
		break;
	case G_LOG_LEVEL_WARNING:
		priority = LOG_WARNING;
		break;
	case G_LOG_LEVEL_MESSAGE:
		priority = LOG_NOTICE;
		break;
	case G_LOG_LEVEL_INFO:
		priority = LOG_INFO;
		break;
	case G_LOG_LEVEL_DEBUG:
		priority = LOG_DEBUG;
		break;
	default:
		priority = LOG_INFO;
	}

	syslog (priority, "%s", message);
}

/** @brief configures logger at start-up
 * 
 * performs basic configuration of the logger. it means that all
 * output will be printed to the console.
 *
 * @param log logger data
 * @return an error code
 */

gint aspamd_logger_early_configure (aspamd_log_data_t *log)
{
	g_assert (log);

	log->file = stdout;
	log->configured = 0;
	g_log_set_default_handler (&aspamd_log_stdio_handler, log);
	return ASPAMD_ERR_OK;

}

/** @brief configures logger
 *
 * reconfigures the logger according to the type. if type is file then
 * file will be opened to append data to. if type is syslog then
 * syslog initialization routine will be invoked.
 *
 * @param log logger data
 * @return an error code
 */

gint aspamd_logger_configure (aspamd_log_data_t *log)
{
	g_assert (log);

	if (log->configured)
	{
		if (log->type == aspamd_log_file)
			fclose (log->file);
		else if (log->type == aspamd_log_console)
			closelog ();
		log->configured = 0;
	}

	if (log->type == aspamd_log_console)
	{
		log->file = stdout;
		g_log_set_handler (G_LOG_DOMAIN, log->level,
				   &aspamd_log_stdio_handler, log);
	}
	else if (log->type == aspamd_log_file)
	{
		log->file = fopen (log->path, "a");
		if (!log->file)
		{
			g_critical ("open log file %s failed: %s",
				    log->path, strerror (errno));
			return ASPAMD_ERR_IO;
		}
		g_log_set_handler (G_LOG_DOMAIN, log->level,
				   &aspamd_log_stdio_handler, log);
	}
	else if(log->type == aspamd_log_syslog)
	{
		if (!log->configured)
			openlog (NULL, LOG_PID | LOG_ODELAY, LOG_DAEMON);
		g_log_set_handler (G_LOG_DOMAIN, log->level,
				   &aspamd_log_syslog_handler, log);
	}
	g_log_set_default_handler (&aspamd_log_void_handler, log);
	log->configured = 1;
	g_debug ("%s logger is configured",
		 ASPAMD_LOGT_TO_STR (log->type));
	return ASPAMD_ERR_OK;
}

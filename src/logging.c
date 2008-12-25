/* 
 * aspamd - advanced spam daemon 
 *
 */

#include <sys/time.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <glib.h>
#include <errors.h>
#include <logging.h>
#include <config.h>

static gchar *default_log_path = ASPAMD_DEFAULT_LOG_PATH;

/*-----------------------------------------------------------------------------*/

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
	int err;
	aspamd_log_data_t *log = data;
	gchar buffer[ASPAMD_MAX_LINE_LEN];
	gint offset = 0, bytes_written = 0;
	struct tm *tm = NULL;
	struct timeval tv;

	g_assert (log);

	if (log->_file_tstamp != aspamd_log_ts_none)
	{
		err = gettimeofday (&tv, NULL);
		if (err == 0 && log->_file_tstamp == aspamd_log_ts_short)
		{
			bytes_written = g_snprintf (buffer + offset,
						    ASPAMD_MAX_LINE_LEN - offset, 
						    "%i.%03i ", (int) tv.tv_sec,
						    (int) tv.tv_usec / 1000);
		}
		else if (err == 0 && log->_file_tstamp == aspamd_log_ts_long)
		{
			tm = localtime (&tv.tv_sec);
			bytes_written = g_snprintf (buffer + offset,
						    ASPAMD_MAX_LINE_LEN - offset, 
						    "%i/%i/%i %i:%i ",
						    tm->tm_mday, tm->tm_mon + 1,
						    1900 + tm->tm_year,
						    tm->tm_hour, tm->tm_min);
		}
		if (bytes_written < ASPAMD_MAX_LINE_LEN)
			offset += bytes_written;
	}

	offset += g_snprintf (buffer + offset, ASPAMD_MAX_LINE_LEN - offset, 
			      "%s[%s]: %s\n", log_domain,
			      aspamd_log_level_to_str (log_level),
			      message);
	bytes_written = fwrite (buffer, 1, offset, log->file);
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

/*-----------------------------------------------------------------------------*/

aspamd_pair_t logs[] = {
	{aspamd_log_syslog, "syslog"},
	{aspamd_log_file, "file"},
	{aspamd_log_console, "console"}
};

aspamd_pair_t log_stamps[] = {
	{aspamd_log_ts_none, "none"},
	{aspamd_log_ts_short, "short"},
	{aspamd_log_ts_long, "long"}
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

/** @brief allocates new logger
 *
 * @param log logger data
 * @return an error code
 */

gint aspamd_logger_allocate (aspamd_log_data_t **new_log)
{
	gint ret = ASPAMD_ERR_OK;
	aspamd_log_data_t *log = NULL;

	log = g_slice_new (aspamd_log_data_t);
	ASPAMD_ERR_IF (!log, ASPAMD_ERR_MEM, "logger allocation failed");
	log->path = default_log_path;
	log->level = ASPAMD_DEFAULT_LOG_LEVEL;
	log->type = ASPAMD_DEFAULT_LOG_TYPE;
	log->configured = FALSE;
	log->_file_tstamp = aspamd_log_ts_long;
	log->file_overwrite = FALSE;

at_exit:
	if (ret == ASPAMD_ERR_OK)
		*new_log = log;
	else
	{
		if (log)
			aspamd_logger_free (log);
		*new_log = NULL;
	}
	return ret;
}

/** @brief configures logger at start-up
 * 
 * performs basic configuration of the logger. it means that all
 * output will be printed to the console.
 *
 * @param log logger data
 * @return an error code
 */

void aspamd_logger_early_configure (aspamd_log_data_t *log)
{
	g_assert (log);

	log->level = ASPAMD_DEFAULT_LOG_LEVEL;
	log->type = aspamd_log_console;
	log->_file_tstamp = aspamd_log_ts_long;
	log->file = stdout;
	log->configured = FALSE;
	g_log_set_handler (G_LOG_DOMAIN, log->level,
				   &aspamd_log_stdio_handler, log);
	g_log_set_default_handler (&aspamd_log_void_handler, log);
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
	gchar *mode = NULL;
	aspamd_pair_t *pair = NULL;

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
		log->_file_tstamp = log->file_tstamp;
		g_log_set_handler (G_LOG_DOMAIN, log->level,
				   &aspamd_log_stdio_handler, log);
	}
	else if (log->type == aspamd_log_file)
	{
		if (log->file_overwrite)
			mode = "w";
		else
			mode = "a";
		log->file = fopen (log->path, mode);
		if (!log->file)
			return ASPAMD_ERR_IO;
		log->_file_tstamp = log->file_tstamp;
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
	log->configured = TRUE;
	pair = code_to_str (logs, log->type);
	g_debug ("logger is configured, type - %s", pair->string);
	return ASPAMD_ERR_OK;
}

/** @brief releases logger resources 
 *
 * @param log logger
 * @return an error code
 */

void aspamd_logger_free (aspamd_log_data_t *log)
{
	g_assert (log);

	if (log->path && log->path != default_log_path)
	{
		g_free (log->path);
		log->path = NULL;
	}

	if (log->configured)
	{
		if (log->type == aspamd_log_file)
			fclose (log->file);
		else if (log->type == aspamd_log_console)
			closelog ();
	}

	g_slice_free1 (sizeof (aspamd_log_data_t), log);
}

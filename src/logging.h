/* 
 * aspamd - advanced spam daemon 
 *
 */

/*! \file logging.h
 *  \brief diagnostic message logging */

#ifndef _ASPAMD_LOGGING_
#define _ASPAMD_LOGGING_

#include <stdio.h>

#define ASPAMD_MAX_LINE_LEN		(512)

#define ASPAMD_LOGT_TO_STR(type)	aspamd_log_type_to_str[type]

/** logger type*/
enum aspamd_log_type
{
	aspamd_log_syslog,
	/*!< log to syslog */
	aspamd_log_file,
	/*!< log to the file using stdio facilities */
	aspamd_log_console
	/*!< log to the console*/
};

/** logger data*/
struct aspamd_log_data
{
	gint type;
	/*!< logger type*/
	GLogLevelFlags level;
	/*!< message level to be passed trough */
	gchar *path;
	/*!< path to the file to log into */
	FILE *file;
	/*!< file stream */
	gint configured;
	/*!< flag describing the state of the logger, values that
	 * differs from zero means that logger is configured */
};

typedef struct aspamd_log_data aspamd_log_data_t;

extern gchar *aspamd_log_type_to_str[];

gint aspamd_logger_early_configure (aspamd_log_data_t *log);
gint aspamd_logger_configure (aspamd_log_data_t *log);
const gchar *aspamd_log_level_to_str (GLogLevelFlags log_level);

#endif

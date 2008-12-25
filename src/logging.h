/* 
 * aspamd - advanced spam daemon 
 *
 */

/*! \file logging.h
 *  \brief diagnostic message logging */

#ifndef _ASPAMD_LOGGING_
#define _ASPAMD_LOGGING_

#include <stdio.h>
#include <pairs.h>

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

/** logger time stamp types */
enum aspamd_log_tstamp
{
	aspamd_log_ts_none,
	/*!< do no add time-stamp */
	aspamd_log_ts_short,
	/*!< short time-stamp */
	aspamd_log_ts_long
	/*!< long time-stamp */
};

/** logger data*/
struct aspamd_log_data
{
	gint _file_tstamp;
	gint type;
	/*!< logger type*/
	GLogLevelFlags level;
	/*!< message level to be passed trough */
	gchar *path;
	/*!< path to the file to log into */
	FILE *file;
	/*!< file stream */
	gboolean configured;
	/*!< flag describing the state of the logger, values that
	 * differs from zero means that logger is configured */
	gint file_tstamp;
	/*!< add time-stamp to the logged messag */
	gboolean file_overwrite;
	/*!< over-write existing file */
};

typedef struct aspamd_log_data aspamd_log_data_t;

extern aspamd_pair_t logs[];
extern aspamd_pair_t log_stamps[];

gint aspamd_logger_allocate (aspamd_log_data_t **new_log);
void aspamd_logger_early_configure (aspamd_log_data_t *log);
gint aspamd_logger_configure (aspamd_log_data_t *log);
const gchar *aspamd_log_level_to_str (GLogLevelFlags log_level);
void aspamd_logger_free (aspamd_log_data_t *log);

#endif

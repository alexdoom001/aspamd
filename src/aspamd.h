/* 
 * aspamd - advanced spam daemon 
 *
*/

/*! \file aspamd.h
 *  \brief global values */

#ifndef _ASPAMD_APSAMD_
#define _ASPAMD_APSAMD_

/*! this structure gathers all global variables */
struct aspamd_context
{
	gchar *config_path;
	/*!< path to the configuration file. initialized by command
	 * line parsing routine.*/
	gint daemonize;
	/*!< daemonization flag. initialized by command line parsing
	 * routine.*/
	gint stub;
	/*!< enable stub mode. do not pass messages to the KAS just
	 * write simple reply and close session */
	aspamd_log_data_t *log;
	/*!< logger data. Partly initialized by configuration file
	 * parsing routine. */
	aspamd_server_t *server;
	/*!< network server data. Partly initialized by configuration
	 * file parsing routine */
	kas_data_t *kas;
	/*!< KAS engine wrapper data */
	aspamd_reactor_t *reactor;
	/*!< event dispatcher */
	gint signal_fd;
	/*!< file descriptor that is returned by signalfd
	 * function. One is used to handle incoming signals. */
	gint timeout;
	/*!< temp variable to store message read time-out value */
	gint pid;
	/*!< process ID */
	gchar *pid_file_path;
	/*!< file to store PID. One is mostly used by rc.d scripts
	 * and start-stop-daemon utility */
	gint server_type;
	gint print_license_info;
};

typedef struct aspamd_context aspamd_context_t;

extern aspamd_context_t context;

#endif

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
	gchar *config_path;	/*!< path to the configuration
				 * file. initialized by command line
				 * parsing routine.*/
	gint daemonize;		/*!< daemonization flag. initialized
				 * by command line parsing routine.*/
	aspamd_log_data_t log;	/*!< logger data. Partly initialized
				 * by configuration file parsing
				 * routine. */
	aspamd_server_t server;	/*!< network server data. Partly
				 * initialized by configuration file
				 * parsing routine */
};

typedef struct aspamd_context aspamd_context_t;

extern aspamd_context_t context;

/* should be moved to config.h populated by autotools */
#define ASPAMD_DEFAULT_LOG_PATH		"aspamd.log"
#define ASPAMD_DEFAULT_LOG_TYPE		aspamd_log_syslog
#define ASPAMD_DEFAULT_LOG_LEVEL	G_LOG_LEVEL_WARNING
#define ASPAMD_DEFAULT_NET_IP		"127.0.0.1"
#define ASPAMD_DEFAULT_NET_PORT		783

#endif

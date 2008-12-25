/* 
 * aspamd - advanced spam daemon 
 *
*/

/*! \file assassin.h
 *  \brief SpamAssassin message description */

#ifndef _ASPAMD_ASSASSIN_
#define _ASPAMD_ASSASSIN_

#define ASSASSIN_MAX_HEAD_SIZE		(256)

/** assassin error codes. it is mostly ripped of Spamd.pm for
 * compatibility reasons. May be reused partly. */
enum assassin_error
{
	assassin_ex_ok		= 0,     /*!< no problems */
	assassin_ex_usage	= 64,    /*!< command line usage error */
	assassin_ex_dataerr	= 65,    /*!< data format error */
	assassin_ex_noinput	= 66,    /*!< cannot open input */
	assassin_ex_nouser	= 67,    /*!< addressee unknown */
	assassin_ex_nohost	= 68,    /*!< host name unknown */
	assassin_ex_unavailable	= 69,    /*!< service unavailable */
	assassin_ex_software	= 70,    /*!< internal software error */
	assassin_ex_oserr	= 71,    /*!< system error (e.g., can't fork) */
	assassin_ex_osfile	= 72,    /*!< critical os file missing */
	assassin_ex_cantcreat	= 73,    /*!< can't create (user) output file */
	assassin_ex_ioerr	= 74,    /*!< input/output error */
	assassin_ex_tempfail	= 75,    /*!< temp failure; user is invited to retry */
	assassin_ex_protocol	= 76,    /*!< remote error in protocol */
	assassin_ex_noperm	= 77,    /*!< permission denied */
	assassin_ex_config	= 78,    /*!< configuration error */
	assassin_ex_timeout	= 79     /*!< read timeout */
};

typedef enum assassin_error assassin_error_t;

/** comman
 * take a look at Mail-SpamAssassin/spamd/PROTOCOL file for details
 */

enum assassin_command
{
	assassin_cmd_check,
	/*!< Just check if the passed message is spam or not and reply
	 * as described below*/
	assassin_cmd_symbols,
	/*!< Check if message is spam or not, and return score plus
	  list of symbols hit */
	assassin_cmd_report,
	/*!< Check if message is spam or not, and return score plus
	 * report*/
	assassin_cmd_report_ifspam,
	/*!< Check if message is spam or not, and return score plus
	  report if the message is spam */
	assassin_cmd_skip,
	/*!< Ignore this message -- client opened connection then
	  changed its mind */
	assassin_cmd_ping,
	/*!< Return a confirmation that spamd is alive */
	assassin_cmd_process,
	/*!< Process this message as described above and return
	  modified message */
	assassin_cmd_tell,
	/*!< Tell what type of we are to process and what should be
	  done with that message.  This includes setting or removing a
	  local or a remote database (learning, reporting, forgetting,
	  revoking). */
	assassin_cmd_headers,
	/*!< Same as PROCESS, but return only modified headers, not
	  body (new in protocol 1.4) */
};

typedef enum assassin_command assassin_command_t;

/** header type
 *
 * take a look at Mail-SpamAssassin/spamd/PROTOCOL file for details
 */
enum assassin_header_type
{
	assassin_hdr_content_length,
	/*!< length of a request or response body, in bytes (generally
	  a requirement as of protocol version 1.2 onwards)*/
	assassin_hdr_spam,
	/*!< filtering status and spam score */
	assassin_hdr_user,
	/*!< Username of the user on whose behalf this scan is being
	  performed. The meaning of this is up to the server; format is that
	  of a traditional UNIX username ([-A-Za-z0-9_]+). it is not
	  supported in aspamd. */
	assassin_hdr_compress,
	/*!< An optional header, sent by the client to the server,
	  whose value may consist of the string "zlib", indicating
	  that the message body transmitted by the client is
	  compressed using Zlib compression.*/
	assassin_hdr_message_class,
	assassin_hdr_remove,
	assassin_hdr_set,
	assassin_hdr_did_set,
	assassin_hdr_did_remove
};

typedef enum assassin_header_type assassin_header_type_t;

/** header data */
struct assassin_header
{
	gint type;
	/*!< header type, take a look at #assassin_header_type to find
	 * out possible values */
	GVariant *value;
	/*!< header value. one type depends on the header type and may
	 * * be string, integer or something else */
};

typedef struct assassin_header assassin_header_t;

/** message type */
enum assassin_message_type
{
	assassin_msg_request,
	/*!< request produced by client */
	assassin_msg_response
	/*!< request formed by server*/
};

typedef enum assassin_message_type assassin_message_type_t;

struct assassin_message
{
	gint	type,
	/*!< message type, take a look at #assassin_message_type to
	 * find out possible values*/
		version_major,
	/*!< major version of the supported protocol */
		version_minor,
	/*!< minor version of the supported protocol */
		command;
	/*!< command, take a look at #assassin_command to find out
	 * possible values*/
	union {
		gint error;
		/*!< error code, valid only for response */
		gchar *client;
		/*!< client identifier */
	};
	GSList *headers;
	/*!< single linked header list of #assassin_header
	 * structures */
	struct
	{
		gpointer buffer;
		/*!< buffer that contains body of the message */
		gint offset;
		/*!< body offset in the content_buffer */
		gint size;
		/*!< body size */
		gboolean auto_free;
		/*!< if it is on then call g_free to release content_buffer */
	}content;
};

typedef struct assassin_message assassin_message_t;

gint assassin_msg_allocate (assassin_message_t **new_message, gint type, gint command,
			    gint major, gint minor);
gint assassin_msg_add_header(assassin_message_t *message, gint type, GVariant *value);
GVariant *assassin_msg_find_header(assassin_message_t *message, gint type);
gint assassin_msg_add_body(assassin_message_t *message, gpointer buffer, gint offset,
			   gint size, gint auto_free);
gint assassin_msg_printf (assassin_message_t *message, gpointer *data, gint *filling);
void assassin_msg_free (assassin_message_t *message);

#endif

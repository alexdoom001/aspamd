/* 
 * aspamd - advanced spam daemon 
 *
*/

/*! \file assassin.h
 *  \brief SpamAssassin message description */

#ifndef _ASPAMD_ASSASSIN_
#define _ASPAMD_ASSASSIN_

#define ASSASSIN_VER_MAJOR		1
#define ASSASSIN_VER_MINOR		4

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
	assassin_hdr_did_remove,
	assassin_hdr_client_address,
	assassin_hdr_helo_name,
	assassin_hdr_mail_from,
	assassin_hdr_rcpt_to,
	assassin_hdr_quarantine
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
	assassin_msg_reply
	/*!< request formed by server*/
};

typedef enum assassin_message_type assassin_message_type_t;

struct assassin_buffer
{
	gchar *data;
	/*!< pointer to the data */
	gint offset;
	/*!< offset where data is placed */
	gint size;
	/*!< total buffer size */
	gboolean allocated;
	/*!< if not zero then call g_free to release buffer */
};

typedef struct assassin_buffer assassin_buffer_t;

gint assassin_buffer_allocate (assassin_buffer_t **new_buffer, int size);
void assassin_buffer_get_data (assassin_buffer_t *buffer, gpointer *data, gint *size);
void assassin_buffer_free (assassin_buffer_t *buffer);

struct assassin_message
{
	gint	type,
	/*!< message type, take a look at #assassin_message_type to
	 * find out possible values*/
		version_major,
	/*!< major version of the supported protocol */
		version_minor,
	/*!< minor version of the supported protocol */
		command,
	/*!< command, take a look at #assassin_command to find out
	 * possible values*/
		error;
	/*!< error code, valid only for response */	
	gchar *ident;
	/*!< software type identifier */
	GSList *headers;
	/*!< single linked header list of #assassin_header
	 * structures */
	const gchar **recipients;
	assassin_buffer_t *content;
};

enum {
	ASSASSIN_BUF_NEW,
	ASSASSIN_BUF_CONTENT
};

typedef struct assassin_message assassin_message_t;

gint assassin_msg_allocate (assassin_message_t **new_message, gint type, const gchar *ident);
gint assassin_msg_add_header(assassin_message_t *message, gint type, GVariant *value);
GVariant *assassin_msg_find_header(assassin_message_t *message, gint type);
gint assassin_msg_add_body(assassin_message_t *message, gpointer buffer, gint offset,
			   gint size, gint allocated);
gint assassin_msg_set_body(assassin_message_t *message, assassin_buffer_t *buffer);
gint assassin_msg_print (assassin_message_t *message, assassin_buffer_t **content,
			 gint mode);
void assassin_msg_free (assassin_message_t *message);

#endif

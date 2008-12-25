/* 
 * aspamd - advanced spam daemon 
 *
 */

#include <stdio.h>
#include <glib.h>
#include "assassin.h"
#include "errors.h"
#include "net.h"

static struct
{
	gint code;
	gchar *representation;
} 
code_to_str[] =
{
	{assassin_ex_ok, "EX_OK"},
	{assassin_ex_usage, "EX_USAGE"},
	{assassin_ex_dataerr, "EX_DATAERR"},
	{assassin_ex_noinput, "EX_NOINPUT"},
	{assassin_ex_nouser, "EX_NOUSER"},
	{assassin_ex_nohost, "EX_NOHOST"},
	{assassin_ex_unavailable, "EX_UNAVAILABLE"},
	{assassin_ex_software, "EX_SOFTWARE"},
	{assassin_ex_oserr, "EX_OSERR"},
	{assassin_ex_osfile, "EX_OSFILE"},
	{assassin_ex_cantcreat, "EX_CANTCREAT"},
	{assassin_ex_ioerr, "EX_IOERR"},
	{assassin_ex_tempfail, "EX_TEMPFAIL"},
	{assassin_ex_protocol, "EX_PROTOCOL"},
	{assassin_ex_noperm, "EX_NOPERM"},
	{assassin_ex_config, "EX_CONFIG"},
	{assassin_ex_timeout, "EX_TIMEOUT"}
};

static char *hdr_type_to_str[] =
{
	"content-length",
	"spam",
	"user",
	"compress",
	"class",
	"remove",
	"set",
	"did_set",
	"did_remove"
};

static char *command_to_str[] =
{
	"CHECK",
	"SYMBOLS",
	"REPORT",
	"REPORT_IFSPAM",
	"SKIP",
	"PING",
	"PROCESS",
	"TELL",
	"HEADERS"
};

static char *msg_type_to_str[] =
{
	"request",
	"response",
};

static gint assassin_hdr_printf (assassin_header_t *header, gchar *buffer, gint size)
{
	gint bytes_written;
	/* for spam header decoding */
	gboolean spam;
	gint numerator, denominator;
	gchar *str;

	g_assert (header && buffer);

	if (header->type == assassin_hdr_content_length)
	{
		bytes_written = snprintf (buffer, size, "%s: %i\r\n",
					  hdr_type_to_str[header->type],
					  g_variant_get_int32 (header->value));
		g_assert (bytes_written);
	}
	else if (header->type == assassin_hdr_user)
	{
		bytes_written = snprintf (buffer, size, "%s: %s\r\n",
					  hdr_type_to_str[header->type],
					  g_variant_get_string (header->value, NULL));
		g_assert (bytes_written);
	}
	else if (header->type == assassin_hdr_spam)
	{
		if (spam)
			str = "true";
		else
			str = "false";
		g_variant_get (header->value, "(bii)", &spam, &numerator, &denominator);
		bytes_written = snprintf (buffer, size, "%s: %s ; %i / %i\r\n",
					  hdr_type_to_str[header->type],
					  str, numerator, denominator);
		g_assert (bytes_written);
	}
	else
	{
		g_warning ("header %s is not supported",
			   hdr_type_to_str[header->type]);
	}
	return bytes_written;
}

/** @brief provides string representation of SpamAssassin error code
 *
 * @param error an error code, take a look at #assassin_error for
 * details.
 * @return pointer to string or NULL
 */

static gchar *assassin_error_to_string (gint error)
{
	int i;

	for (i = 0; i < sizeof (code_to_str)/sizeof (code_to_str[0]); i++)
	{
		if (code_to_str[i].code == error)
			return code_to_str[i].representation;
	}
	return NULL;
}


/*-----------------------------------------------------------------------------*/

/** @brief allocates new SpamAssassin message
 *
 * if allocation is successfully then some fields are initialized by
 * parameters passed to the function.
 *
 * @param new_message new allocated message or NULL if failed
 * @param major protocol major version number
 * @param minor protocol minor version number
 * @param type type of the message, take a look at
 * #assassin_message_type for details
 * @return #ASPAMD_ERR_OK or #ASPAMD_ERR_MEM
 */

gint assassin_msg_allocate (assassin_message_t **new_message, gint type, gint command,
			    gint major, gint minor)
{
	gint ret = ASPAMD_ERR_OK;
	assassin_message_t *message = NULL;

	message = g_slice_new (assassin_message_t);
	if (!message)
	{
		g_critical ("memory allocation failed");
		ret = ASPAMD_ERR_MEM;
		goto at_exit;
	}
	message->type = type;
	message->command = command;
	message->version_major = major;
	message->version_minor = minor;
	message->content.buffer = NULL;
	message->content.auto_free = 0;

at_exit:
	if (ret == ASPAMD_ERR_OK)
		*new_message = message;
	else
	{
		*new_message = NULL;
		assassin_msg_free (message);
	}
	g_debug ("new message %p, type - %s, command - %s", message, msg_type_to_str[type],
		command_to_str[command]);
		
	return ret;
}

/** @brief adds new header to the message
 *
 * @param message a message
 * @param type header type, take a look at #assassin_header_type_t for details.
 * @param value header value
 * #assassin_message_type for details
 * @return #ASPAMD_ERR_OK, #ASPAMD_ERR_MEM or #ASPAMD_ERR_MSG if
 * such header already exists.
 */

gint assassin_msg_add_header(assassin_message_t *message, gint type,
			     GVariant *value)
{
	assassin_header_t *header;

	g_assert (message && value);

	if (message->headers)
	{
		if (assassin_msg_find_header (message, type))		
		{
			g_warning ("header `%s' is already added to the message %p",
				   hdr_type_to_str[type], message);
			return ASPAMD_ERR_MSG;
		}
	}
	header = g_slice_new(assassin_header_t);
	if (!header)
	{
		g_critical ("memory allocation failed");
		return ASPAMD_ERR_MEM;
	}
	header->type = type;
	header->value = value;
	message->headers = g_slist_append (message->headers, header);
	g_assert (message->headers);
	g_debug ("header `%s' is added to the message %p", hdr_type_to_str[type],
		 message);
	
	return ASPAMD_ERR_OK;
}

/** @brief finds header in the message, if such one exists then value
 * is returned.
 *
 * @param message a message
 * @param type header type, take a look at #assassin_header_type_t for details.
 * @return header value or NULL
 */

GVariant *assassin_msg_find_header(assassin_message_t *message, gint type)
{
	GSList	*iter;
	assassin_header_t *header;

	g_assert (message);

	for (iter = message->headers;
	     iter;
	     iter = g_slist_next (iter))
	{
		header = (assassin_header_t*)iter->data;
		if (header->type  == type)
			return header->value;
	}
	return NULL;
}

/** @brief adds new content to the message
 *
 * @param message a message
 * @param buffer buffer that contains body
 * @param offset offset in the buffer
 * @param auto_free call g_free to release buffer during destructor
 * @return #ASPAMD_ERR_OK, #ASPAMD_ERR_MSG if body is already attached
 */

gint assassin_msg_add_body(assassin_message_t *message, gpointer buffer, gint offset,
			   gint size, gint auto_free)
{
	if (message->content.buffer)
	{
		g_critical ("body is already attached to the message %p", message);
		return ASPAMD_ERR_MSG;
	}
	message->content.buffer = buffer;
	message->content.offset = offset;
	message->content.size = size;
	message->content.auto_free = auto_free;
	g_debug ("body of %i bytes is added to the message %p", size, message);
	return ASPAMD_ERR_OK;
}

/** @brief prints message to the buffer
 *
 * @param message a message to be released
 * @param data pointer to the allocated buffer
 * @param filling actual size of the serialized message
 * @return #ASPAMD_ERR_OK or #ASPAMD_ERR_MSG if it is not enough
 * free space in the buffer.
 */

gint assassin_msg_printf (assassin_message_t *message, gpointer *data, gint *filling)
{
	gint ret = ASPAMD_ERR_OK;
	gint size, bytes_written;
	gchar *buffer = NULL, *offset = NULL;
	GSList *iter = message->headers;
	assassin_header_t *header;

	g_assert (message && data && filling);

	if (message->type == assassin_msg_request)
	{
		g_critical ("SpamAssassin request serialization is not supported");
		ret = ASPAMD_ERR_MSG;
		goto at_exit;
	}

	size =  g_variant_get_int32(assassin_msg_find_header (
					    message, assassin_hdr_content_length)) +
		ASSASSIN_MAX_HEAD_SIZE;

	offset = buffer = g_malloc (size);
	if (!buffer)
	{
		g_critical ("memory allocation failed");
		ret = ASPAMD_ERR_MEM;
		goto at_exit;
	}

	bytes_written = snprintf (offset, size,
				  "SPAMD/%i.%i %i %s\r\n",
				  message->version_major,
				  message->version_minor,
				  message->error,
				  assassin_error_to_string (message->error));

	g_assert (bytes_written > 0);
	offset += bytes_written;
	size -= bytes_written;

	for (iter = message->headers;
	     iter;
	     iter = g_slist_next (iter))
	{
		header = (assassin_header_t*)iter->data;
		bytes_written = assassin_hdr_printf(header, offset, size);
		g_assert (bytes_written > 0);
		offset += bytes_written;
		size -= bytes_written;
	}

	if (message->content.buffer)
	{
		bytes_written = snprintf (offset, size,
					  "\r\n%s",
					  (gchar *) message->content.buffer +
					  message->content.offset);
		g_assert (bytes_written > 0);
		offset += bytes_written;
		size -= bytes_written;
	}

	if (offset == buffer + size)
	{
		g_critical ("message has been truncated, please adjust\
ASPAMD_SESSION_MAX_HEADER_SIZE variable ");
		ret = ASPAMD_ERR_MSG;
		goto at_exit;
	}

at_exit:
	if (ret == ASPAMD_ERR_OK)
	{
		*data = buffer;
		*filling = offset - buffer;
	}
	else
	{
		*data = NULL;
		*filling = 0;
		if (buffer)
			g_free (buffer);
	}
	return ret;
}

/** @brief releases SpamAssassin message
 *
 * releases messages and all internally allocated resources
 *
 * @param message a message to be released
 */

void assassin_msg_free (assassin_message_t *message)
{
	GSList *iter = message->headers;
	assassin_header_t *header;

	g_assert (message);

	if (message->headers)
	{
		for (iter = message->headers;
		     iter;
		     iter = g_slist_next (iter))
		{
			header = iter->data;
			if (header->value)
				g_variant_unref (header->value);
			g_slice_free1 (sizeof (assassin_header_t), header);
		}
		g_slist_free (message->headers);
	}
	if (message->type == assassin_msg_request)
	{
		if (message->client)
			g_free (message->client);
	}
	if (message->content.auto_free && message->content.buffer)
		g_free (message->content.buffer);

	g_slice_free1 (sizeof (assassin_message_t), message);
}


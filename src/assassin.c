/* 
 * aspamd - advanced spam daemon 
 *
 */

#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <assassin.h>
#include <errors.h>
#include <pairs.h>
#include <config.h>

static gint assassin_print_header (assassin_header_t *header, gchar *buffer, gint *offset,
				   gint size)
{
	gint ret = ASPAMD_ERR_OK;
	gint bytes = 0;
	/* for spam header decoding */
	gboolean spam;
	gint numerator, denominator;
	gchar *str;
	aspamd_pair_t *pair;

	g_assert (header && buffer && offset);

	pair = code_to_str (assassin_hdrs, header->type);

	switch (header->type)
	{
	case  assassin_hdr_content_length:
		bytes = g_snprintf (buffer, size, "%s: %i\r\n",
				    pair->string,
				    g_variant_get_int32 (header->value));
		break;
	case assassin_hdr_user:
		bytes = snprintf (buffer, size, "%s: %s\r\n",
				  pair->string,
				  g_variant_get_string (header->value, NULL));
		break;
	case assassin_hdr_spam:
	{
		g_variant_get (header->value, "(bii)", &spam, &numerator, &denominator);
		if (spam)
			str = "true";
		else
			str = "false";
		bytes = snprintf (buffer, size, "%s: %s ; %i / %i\r\n",
				  pair->string,
				  str, numerator, denominator);
		break;
	}
	case assassin_hdr_quarantine:
	{
		if (g_variant_get_boolean (header->value))
			str = "true";
		else
			str = "false";
		bytes = snprintf (buffer, size, "%s: %s\r\n", pair->string, str);
		break;
	}
	default:
		ASPAMD_ERR (ASPAMD_ERR_MSG, "header %s is not supported", pair->string);
	}
	if (bytes < size - 1)
		*offset = bytes;
at_exit:
	return ret;
}

static gint assassin_print_head (assassin_message_t *message, gchar *buffer, gint *offset,
				 gint size)
{
	gint ret = ASPAMD_ERR_OK;
	GSList *iter = message->headers;
	gint bytes = 0;
	const gchar *error_str = NULL;
	gchar *ptr = buffer;
	assassin_header_t *header = NULL;
	aspamd_pair_t *pair = NULL;

	g_assert (message && buffer && offset);

	if (message->type == assassin_msg_reply)
	{

		if (message->command != assassin_cmd_ping || message->error != assassin_ex_ok)
		{
			pair = code_to_str (assassin_errs, message->error);
			error_str = pair->string;
		}
		else
			error_str = "PONG";

		bytes = g_snprintf (ptr, size, "SPAMD/%i.%i %i %s\r\n",
				    message->version_major, message->version_minor,
				    message->error, error_str);
	}
	else if (message->type == assassin_msg_request)
	{
		pair = code_to_str (assassin_cmds, message->command);
		bytes = g_snprintf (ptr, size, "%s %s/%i.%i\r\n", pair->string,
				    message->ident, message->version_major,
				    message->version_minor);
	}
	else
		ASPAMD_ERR (ASPAMD_ERR_MSG, 
			    "message %p: unknown message type - %i", message, message->type);
	

	if (bytes < size - 1)
	{
		ptr += bytes;
		size -= bytes;
	}
	else
		ASPAMD_ERR (ASPAMD_ERR_MSG,
			    "message %p: failed to write first line of the message header",
			    message);		

	for (iter = message->headers; iter; iter = g_slist_next (iter))
	{
		header = (assassin_header_t*) iter->data;
		ret = assassin_print_header(header, ptr, &bytes, size);
		
		if (ret == ASPAMD_ERR_OK)
		{
			ptr += bytes;
			size -= bytes;
		}
		else
		{
			pair = code_to_str (assassin_hdrs, header->type);
			ASPAMD_ERR (ASPAMD_ERR_ERR,"message %p: failed to write header: `%s'",
				    message, pair->string);
		}
	}	

at_exit:
	if (ret == ASPAMD_ERR_OK)
		*offset = (glong) ptr - (glong) buffer;
	return ret;
}

static gint assassin_print_body (assassin_message_t *message, gchar *buffer, gint *offset,
				 gint size)
{
	gint ret = ASPAMD_ERR_OK;
	gint body_size, bytes;
	gchar *body = NULL;

	if (message->content)
	{
		assassin_buffer_get_data (message->content, (gpointer *)&body, &body_size);
		body_size += 3; /* \r\n + \0 */
	}
	else
	{
		body_size = 3; /* \r\n + \0 */
		body = "";
	}
	ASPAMD_ERR_IF (body_size > size, ASPAMD_ERR_MSG,
		       "message %p: body does not fit the buffer", message);
	bytes = g_snprintf (buffer, body_size, "\r\n%s", body);
	*offset = bytes;

at_exit:
	return ret;
}

/*-----------------------------------------------------------------------------*/

gint assassin_buffer_allocate (assassin_buffer_t **new_buffer, int size)
{
	gint ret = ASPAMD_ERR_OK;
	assassin_buffer_t *buffer= NULL;

	buffer = g_slice_new (assassin_buffer_t);
	ASPAMD_ERR_IF (!buffer, ASPAMD_ERR_MEM, "failed to allocate new buffer");
	buffer->allocated = 1;
	if (size > 0)
	{
		buffer->data = g_malloc (size);
		ASPAMD_ERR_IF (!buffer->data, ASPAMD_ERR_MEM,
			       "failed to allocate new buffer");
		buffer->size = size;
		buffer->offset = 0;
	}
	else
	{
		buffer->data = NULL;
		buffer->size = 0;
		buffer->offset = 0;
	}
	g_debug ("new buffer at %p is allocated, data - %p, offset - %i, size %i", 
		 buffer, buffer->data, buffer->offset, buffer->size);
at_exit:
	if (ret == ASPAMD_ERR_OK)
		*new_buffer = buffer;
	else
	{
		*new_buffer = NULL;
		assassin_buffer_free (buffer);
	}
		
	return ret;
}

/** @brief extracts actual data beginning and size
 *
 * @param buffer a buffer
 * @param data pointer to return data location
 * @param size pointer to return data size
 */

void assassin_buffer_get_data (assassin_buffer_t *buffer, gpointer *data, gint *size)
{
	g_assert (buffer && data && size);

	if (buffer->data)
	{
		*data = buffer->data + buffer->offset;
		*size = buffer->size - buffer->offset;
	}
	else
	{
		*data = NULL;
		*size = 0;
	}
}

/** @brief releases a buffer
 *
 * if buffer is marked as free internal data will be released too.
 *
 * @param buffer a buffer
 */

void assassin_buffer_free (assassin_buffer_t *buffer)
{
	g_assert (buffer);

	g_debug ("buffer %p is about to be released", buffer);
	if (buffer->allocated)
	{
		g_free (buffer->data);
		buffer->data = NULL;
	}
	g_slice_free1 (sizeof (assassin_buffer_t), buffer);
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

gint assassin_msg_allocate (assassin_message_t **new_message, gint type, const gchar *ident)
{
	gint ret = ASPAMD_ERR_OK;
	assassin_message_t *message = NULL;
	aspamd_pair_t *pair = NULL;

	message = g_slice_new (assassin_message_t);
	ASPAMD_ERR_IF (!message, ASPAMD_ERR_MEM,
		       "assassin message allocation failed");
	message->type = type;
	message->command = -1;
	message->version_major = ASSASSIN_VER_MAJOR;
	message->version_minor = ASSASSIN_VER_MINOR;
	message->headers = NULL;
	message->content = NULL;
	message->recipients = NULL;
	if (ident)
		message->ident = g_strdup (ident);
	else
	{
		if (type == assassin_msg_request)
			message->ident = g_strdup ("SPAMC");
		else if (type == assassin_msg_reply)
			message->ident = g_strdup ("SPAMD");
		else
			message->ident = NULL;
	}

at_exit:
	if (ret == ASPAMD_ERR_OK)
		*new_message = message;
	else
	{
		*new_message = NULL;
		assassin_msg_free (message);
	}
	pair = code_to_str (assassin_msgs, type);
	g_debug ("message at %p is allocated: type - %s, ident - %s",
		 message, pair->string, message->ident);
		
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
	aspamd_pair_t *pair = NULL;

	g_assert (message && value);

	pair = code_to_str (assassin_hdrs, type);

	if (message->headers)
	{
		if (assassin_msg_find_header (message, type))		
		{
			g_warning ("message %p: header `%s' is already added",
				   message, pair->string);
			return ASPAMD_ERR_MSG;
		}
	}
	header = g_slice_new(assassin_header_t);
	if (!header)
	{
		g_critical ("header allocation failed");
		return ASPAMD_ERR_MEM;
	}
	header->type = type;
	header->value = value;
	message->headers = g_slist_append (message->headers, header);
	g_assert (message->headers);
	g_debug ("message %p: header `%s' is added",
		 message, pair->string);
	
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
 * @param allocated call g_free to release buffer during destructor
 * @return #ASPAMD_ERR_OK, #ASPAMD_ERR_MSG if body is already attached
 */

gint assassin_msg_add_body(assassin_message_t *message, gpointer buffer, gint offset,
			   gint size, gint allocated)
{
	gint ret = ASPAMD_ERR_OK;

	g_assert (message && buffer);

	if (message->content)
	{
		assassin_buffer_free (message->content);
		message->content = NULL;
	}
	ret = assassin_buffer_allocate (&message->content, 0);
	ASPAMD_ERR_CHECK (ret);
	message->content->data = buffer;
	message->content->offset = offset;
	message->content->size = size;
	message->content->allocated = allocated;
	ret = assassin_msg_add_header (message, assassin_hdr_content_length,
				       g_variant_new_int32 (size));
	ASPAMD_ERR_CHECK (ret);
	g_debug ("message %p: body of %i bytes is attached", message, size);
at_exit:
	return ret;
}

gint assassin_msg_set_body(assassin_message_t *message, assassin_buffer_t *buffer)
{
	if (message->content)
	{
		assassin_buffer_free (message->content);
		message->content = NULL;
	}
	message->content = buffer;
	g_debug ("message %p: body of %i bytes is attached", message, buffer->size);
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

gint assassin_msg_print (assassin_message_t *message, assassin_buffer_t **content,
			 gint mode)

{
	gint ret = ASPAMD_ERR_OK;
	assassin_buffer_t *buffer = NULL;
	gchar *head_buffer = NULL, *buf = NULL;
	gint offset = 0, size = 0;

	if (mode == ASSASSIN_BUF_NEW)
	{
		size = g_variant_get_int32(
			assassin_msg_find_header (message, assassin_hdr_content_length)) +
			ASSASSIN_MAX_HEAD_SIZE;
		ret = assassin_buffer_allocate (&buffer, size);
		ASPAMD_ERR_CHECK (ret);
		buf = buffer->data;
		ret = assassin_print_head (message, buf, &offset, size);
		ASPAMD_ERR_CHECK (ret);
		buf += offset;
		size -= offset;
		ret = assassin_print_body (message, buf, &offset, size);
		ASPAMD_ERR_CHECK (ret);
		size -= offset;
		buffer->size -= size;
	}
	else if (mode == ASSASSIN_BUF_CONTENT)
	{
		if (message->content->allocated)
		{
			ret = assassin_buffer_allocate (&buffer, 0);
			ASPAMD_ERR_CHECK (ret);
			*buffer = *message->content;
			buffer->allocated = 0;
		}
		else
			buffer = message->content;

		head_buffer = g_malloc (ASSASSIN_MAX_HEAD_SIZE);
		ASPAMD_ERR_IF (!head_buffer, ASPAMD_ERR_MEM,
			       "message %p: failed to allocated new buffer",
			       message);
		ret = assassin_print_head (message, head_buffer, &size,
					   ASSASSIN_MAX_HEAD_SIZE);
		ASPAMD_ERR_CHECK (ret);
		ASPAMD_ERR_IF (size + 2 > buffer->offset, ASPAMD_ERR_MSG,
			       "message %p: message head does not fit the buffer",
			       message);
		sprintf (head_buffer + size, "\r\n");
		size += 2;
		buffer->offset -= size;
		buffer->size += size;
		memcpy (buffer->data + buffer->offset, head_buffer, size);
	}

at_exit:
	if (head_buffer)
		g_free (head_buffer);
	if (ret == ASPAMD_ERR_OK)
		*content = buffer;
	else
	{
		*content = NULL;
		if (buffer)
		{
			assassin_buffer_free (buffer);
			buffer = NULL;
		}
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
	GSList *iter;
	assassin_header_t *header;

	if (!message)
		return;

	g_debug ("message %p is about to be released", message);

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
	if (message->ident)
		g_free (message->ident);
	if (message->recipients)
		g_free (message->recipients);
	if (message->content)
		assassin_buffer_free (message->content);

	g_slice_free1 (sizeof (assassin_message_t), message);
}

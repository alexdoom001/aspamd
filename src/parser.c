/* 
 * aspamd - advanced spam daemon 
 *
 */

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <parser.h>
#include <errors.h>
#include <pairs.h>

static gint get_line_len (const gchar *buffer, gint size);
static void parser_dump_data (assassin_parser_t *parser, const gchar *buffer, gint size);

enum assassin_prs_1line
{
	assassin_1l_command = 1,
	assassin_1l_ident,
	assassin_1l_major,
	assassin_1l_minor,
	assassin_1l_err_code,
	assassin_1l_err_desc,
	assassin_1l_finished
};

static gint parse_request_1_line (assassin_parser_t *parser, GMatchInfo *match_info,
				  const gchar *buffer, gint offset)
{
	gint ret = ASPAMD_ERR_OK;
	gchar *token = NULL;
	gint state = assassin_1l_command, tok_num = 1;
	/* extracted */
	gint command = -1, major, minor;
	gchar *ident = NULL;
	aspamd_pair_t *pair;

	while (state != assassin_1l_finished)
	{
		token = g_match_info_fetch (match_info, tok_num);
		switch (state)
		{
		case assassin_1l_command:
		{
			pair = str_to_code (assassin_cmds, token);
			ASPAMD_ERR_IF (pair->code == -1, ASPAMD_ERR_PARSER,
				       "parser %p: unknown command: %s",
				       parser, token);
			command = pair->code;
			state = assassin_1l_ident;
			break;
		}
		case assassin_1l_ident:
		{
			ident = token;
			token = NULL;
			state = assassin_1l_major;
			break;
		}
		case assassin_1l_major:
		{
			major = atoi (token);
			state = assassin_1l_minor;
			break;
		}
		case assassin_1l_minor:
		{
			minor = atoi (token);
			state = assassin_1l_finished;
			break;
		}
		}
		if (token)
		{
			g_free (token);
			token = NULL;
		}
		tok_num++;
	}
	ret = assassin_msg_allocate (&parser->message, parser->type, ident);
	ASPAMD_ERR_CHECK (ret);
	parser->message->command = command;
	parser->message->version_major = major;
	parser->message->version_minor = minor;
	g_debug ("parser %p: command - %s, major - %i, minor - %i",
		 parser, pair->string, major, minor);
at_exit:
	if (token)
		g_free (token);
	if (ident)
		g_free (ident);
	return ret;
}

static gint parse_reply_1_line (assassin_parser_t *parser, GMatchInfo *match_info,
				const gchar *buffer, gint offset)
{
	gint ret = ASPAMD_ERR_OK;
	gchar *token = NULL;
	gint state = assassin_1l_ident, tok_num = 1;
	/* extracted */
	gint major, minor, error;
	gchar *ident = NULL;
	aspamd_pair_t *pair = NULL;

	while (state != assassin_1l_finished)
	{
		token = g_match_info_fetch (match_info, tok_num);
		switch (state)
		{
		case assassin_1l_ident:
		{
			ident = token;
			token = NULL;
			state = assassin_1l_major;
			break;
		}
		case assassin_1l_major:
		{	
			major = atoi (token);
			state = assassin_1l_minor;
			break;
		}
		case assassin_1l_minor:
		{
			minor = atoi (token);
			state = assassin_1l_err_code;
			break;
		}
		case assassin_1l_err_code:
		{
			error = atoi (token);
			pair = code_to_str (assassin_errs, error);
			ASPAMD_ERR_IF (pair->code == -1, ASPAMD_ERR_PARSER,
				       "parser %p: error code unknown: %i",
				       parser, error);
			state = assassin_1l_finished;
			break;
		}
		}
		if (token)
		{
			g_free (token);
			token = NULL;
		}
		tok_num++;
	}
	ret = assassin_msg_allocate (&parser->message, parser->type, ident);
	ASPAMD_ERR_CHECK (ret);
	parser->message->version_major = major;
	parser->message->version_minor = minor;
	parser->message->error = error;
	g_debug ("parser %p: error - %s, major - %i, minor - %i",
		 parser, pair->string, major, minor);
at_exit:
	if (ident)
		g_free (ident);
	if (token)
		g_free (token);
	return ret;
}

static gint parse_1_line (assassin_parser_t *parser, const gchar *buffer,
			  gint *offset, gint size, gint *completed)
{
	gint ret = ASPAMD_ERR_OK;
	GMatchInfo *match_info = NULL;
	GError *gerr = NULL;
	gint start, end;
	gboolean match;

	g_assert (parser && buffer && offset);

	if (get_line_len (buffer + *offset, size - *offset) < 0)
		return ASPAMD_ERR_OK;

	if (!parser->reg_exp)
	{
		switch (parser->type) 
		{
		case assassin_msg_request:
			parser->reg_exp =  g_regex_new (
				"^([[:alpha:]]+)\\s+([[:alpha:]]+)/(\\d+)\\.(\\d+)\\r\\n",
				G_REGEX_OPTIMIZE, G_REGEX_MATCH_ANCHORED, &gerr);
			break;
		case assassin_msg_reply:
			parser->reg_exp =  g_regex_new (
				"^([[:alpha:]]+)/(\\d+)\\.(\\d+)\\s+(\\d+)\\s+([[:alpha:]_]+)\\r\\n",
				G_REGEX_OPTIMIZE, G_REGEX_MATCH_ANCHORED, &gerr);
			break;
		}
		ASPAMD_ERR_IF (gerr, ASPAMD_ERR_PARSER,
			       "parser %p: regular expression error: %s",
			       parser, gerr->message);
	}

	match = g_regex_match_full (parser->reg_exp, buffer, size, *offset,
				    0, &match_info, &gerr);
	ASPAMD_ERR_IF (gerr, ASPAMD_ERR_PARSER,"parser %p: header 1 line parsing error: %s",
		       parser, gerr->message);

	if(!match)
	{
		parser_dump_data (parser, buffer + *offset, size - *offset);
		ASPAMD_ERR (ASPAMD_ERR_PARSER, "parser %p: failed to parse header 1 line",
			    parser);
	}

	if (g_match_info_matches (match_info))
	{
		if (parser->type == assassin_msg_request)
			ret = parse_request_1_line (parser, match_info, buffer, *offset);
		else
			ret = parse_reply_1_line (parser, match_info, buffer, *offset);
		ASPAMD_ERR_CHECK (ret);
		g_assert (g_match_info_fetch_pos (match_info, 0, &start, &end));
		*offset += end - start;
		*completed = 1;
	}
at_exit:
	if (gerr)
		g_error_free (gerr);
	if (match_info)
		g_match_info_free (match_info);
	if (ret != ASPAMD_ERR_OK)
		*completed = 0;
	return ret;
}

static gint process_spam_header(assassin_parser_t *parser, gchar* value)
{
	gint ret = ASPAMD_ERR_OK;
	GRegex *reg_exp = NULL;
	GError *gerr = NULL;
	GMatchInfo *match_info = NULL;
	gboolean spam;
	gint numerator, denominator;
	gchar *token = NULL;
	gboolean match;

	reg_exp =  g_regex_new (
		"([[:alpha:]]+)\\s*;\\s*(\\d+)\\s*/\\s*(\\d+)",
		G_REGEX_OPTIMIZE, G_REGEX_MATCH_ANCHORED, &gerr);
	ASPAMD_ERR_IF (gerr, ASPAMD_ERR_PARSER, "parser %p: regular expression error: %s",
			    parser, gerr->message);

	match = g_regex_match_full (reg_exp, value, -1, 0,
				    0, &match_info, &gerr);

	ASPAMD_ERR_IF (gerr, ASPAMD_ERR_PARSER, "parser %p: `spam' header parsing error: %s",
			    parser, gerr->message);

	ASPAMD_ERR_IF(!match, ASPAMD_ERR_PARSER,
		      "parser %p: `spam' header parsing failed, buffer - %s",
		      parser, value);

	if (g_match_info_matches (match_info))
	{
		token = g_match_info_fetch (match_info, 1);
		g_assert (token);
		if (g_ascii_strcasecmp (token, "true") == 0)
			spam = TRUE;
		else if (g_ascii_strcasecmp (token, "false") == 0)
			spam = FALSE;
		else
			ASPAMD_ERR (ASPAMD_ERR_PARSER, 
				    "parser %p: `spam' header qualifier `%s' is unknown",
				    parser, token);
		g_free (token);

		token = g_match_info_fetch (match_info, 2);
		g_assert (token);
		numerator = atoi (token);
		g_free (token);

		token = g_match_info_fetch (match_info, 3);
		g_assert (token);
		denominator = atoi (token);
		g_free (token);
		token = NULL;

		ret = assassin_msg_add_header (parser->message, assassin_hdr_spam,
					       g_variant_new ("(bii)", spam,
							      numerator, denominator));
		ASPAMD_ERR_CHECK (ret);
	}

at_exit:
	if (gerr)
		g_error_free (gerr);
	if (match_info)
		g_match_info_free (match_info);
	if (reg_exp)
		g_regex_unref (reg_exp);
	if (token)
		g_free (token);
	return ret;
}

static gint process_rcpt_to_header(assassin_message_t *message, GVariant *value)
{
	assassin_header_t *header;
	aspamd_pair_t *pair = NULL;

	g_assert (message && value);

	pair = code_to_str (assassin_hdrs, assassin_hdr_rcpt_to);

	header = g_slice_new(assassin_header_t);
	if (!header)
	{
		g_critical ("header allocation failed");
		return ASPAMD_ERR_MEM;
	}
	header->type = assassin_hdr_rcpt_to;
	header->value = value;
	message->headers = g_slist_append (message->headers, header);
	g_assert (message->headers);
	g_debug ("message %p: header `%s' is added",
		 message, pair->string);

	return ASPAMD_ERR_OK;
}

static gint process_header (assassin_parser_t *parser, gchar *header, gchar* value)
{
	gint ret = ASPAMD_ERR_OK;
	aspamd_pair_t *pair = NULL;

	g_assert (parser && header && value);

	pair = str_to_code (assassin_hdrs, header);
	ASPAMD_ERR_IF (pair->code == -1, ASPAMD_ERR_PARSER,
		       "parser %p: header `%s' is not supported by the current protocol "
		       "version", parser, header);

	switch (pair->code)
	{
	case assassin_hdr_content_length:
	{
		parser->body_size = atoi (value);
		ret = assassin_msg_add_header (parser->message, assassin_hdr_content_length,
					       g_variant_new_int32 (parser->body_size));
		ASPAMD_ERR_CHECK (ret);
		break;
	}
	case assassin_hdr_user:
	{
		ret = assassin_msg_add_header (parser->message, assassin_hdr_user,
					       g_variant_new_string (value));
		ASPAMD_ERR_CHECK (ret);
		break;
	}
	case assassin_hdr_spam:
	{
		ret = process_spam_header (parser, value);
		ASPAMD_ERR_CHECK (ret);
		break;
	}
	case assassin_hdr_client_address:
	{
		ret = assassin_msg_add_header (parser->message, assassin_hdr_client_address,
					       g_variant_new_string (value));
		ASPAMD_ERR_CHECK (ret);
		break;
	}
	case assassin_hdr_helo_name:
	{
		ret = assassin_msg_add_header (parser->message, assassin_hdr_helo_name,
					       g_variant_new_string (value));
		ASPAMD_ERR_CHECK (ret);
		break;
	}
	case assassin_hdr_mail_from:
	{
		ret = assassin_msg_add_header (parser->message, assassin_hdr_mail_from,
					       g_variant_new_string (value));
		ASPAMD_ERR_CHECK (ret);
		break;
	}
	case assassin_hdr_rcpt_to:
	{
		ret = process_rcpt_to_header (parser->message, g_variant_new_string (value));
		ASPAMD_ERR_CHECK (ret);
		break;
	}
	default:
		g_critical ("parser %p: header `%s' is not supported by the parser, \
omitting", parser, header);
	}

at_exit:
	g_free (header);
	g_free (value);

	return ret;
}

static gint parse_headers (assassin_parser_t *parser, const gchar *buffer,
			   gint *offset, gint size, gint *completed)
{
	gint ret = ASPAMD_ERR_OK;
	GMatchInfo *match_info = NULL;
	GError *gerr = NULL;
	gint start, end;
	gboolean match;

	g_assert (parser && buffer && offset);

	switch (get_line_len (buffer + *offset, size - *offset))
	{
	case -1:
		return ASPAMD_ERR_OK;
	case 0:
		g_debug ("parser %p: no more headers", parser);
		*completed = 1;
		return ASPAMD_ERR_OK;
	}

	if (!parser->reg_exp)
	{
		parser->reg_exp =  g_regex_new (
			"([[:alnum:]-]+)\\s*:\\s*(.+)\\r\\n",
			G_REGEX_OPTIMIZE | G_REGEX_MULTILINE,
			G_REGEX_MATCH_ANCHORED, &gerr);
		ASPAMD_ERR_IF (gerr, ASPAMD_ERR_PARSER, 
			       "parser %p: regular expression error: %s",
			       parser, gerr->message);
	}

	match = g_regex_match_full (parser->reg_exp, buffer, size, *offset,
				    0, &match_info, &gerr);

	ASPAMD_ERR_IF (gerr, ASPAMD_ERR_PARSER, "parser %p: header parsing error: %s",
		       parser, gerr->message);

	if(!match)
	{
		parser_dump_data(parser, buffer + *offset, size - *offset);
		ASPAMD_ERR (ASPAMD_ERR_PARSER, "parser %p: failed to parse header", parser);
	}
	

	while (g_match_info_matches (match_info))
	{
		ret = process_header (parser, g_match_info_fetch (match_info, 1),
				      g_match_info_fetch (match_info, 2));
		ASPAMD_ERR_CHECK (ret);

		g_assert (g_match_info_fetch_pos (match_info, 0, &start, &end));
		*offset += end - start;

		switch (get_line_len (buffer + *offset, size - *offset))
		{
		case -1:
			goto at_exit;
		case 0:
			g_debug ("parser %p: no more headers", parser);
			*completed = 1;
			goto at_exit;
		default:
			g_match_info_next (match_info, &gerr);
			ASPAMD_ERR_IF (gerr, ASPAMD_ERR_PARSER,
				       "parser %p: header parsing error: %s",
				       parser, gerr->message);
		}
	}
	*completed = 1;

at_exit:
	if (gerr)
		g_error_free (gerr);
	if (match_info)
		g_match_info_free (match_info);
	if (ret != ASPAMD_ERR_OK)
		*completed = 0;
	return ret;
}

static gint get_line_len (const gchar *buffer, gint size)
{
	gint state = 0, bytes_checked = size;

	while (bytes_checked > 0)
	{
		switch (state)
		{
		case 0:
			if (*buffer == '\r')
				state = 1;
			break;
		case 1:
			if (*buffer == '\n')
				return size - bytes_checked - 1;
			else
				state = 0;
			break;
		}
		bytes_checked --;
		buffer ++;
	}
	return -1;
}

static void parser_dump_data (assassin_parser_t *parser, const gchar *buffer, gint size)
{
	gchar *sub_string = NULL, *clean_string = NULL;

	if (size > 60)
		size = 60;
	sub_string = g_strndup (buffer, size);
	g_assert (sub_string);
	clean_string = g_strescape (sub_string, NULL);
	g_assert (clean_string);
	g_critical ("parser %p: data dump: %s", parser, clean_string);
	g_free (sub_string);
	g_free (clean_string);
}

/*-----------------------------------------------------------------------------*/

/** @brief allocates new parser to parse SpamAssassin messages.
 *
 * @param new_parser storage to save pointer to new parser
 * @return pointer #ASPAMD_ERR_OK or #ASPAMD_ERR_MEM
 */

gint assassin_parser_allocate (assassin_parser_t **new_parser, gint type, gint verbose)
{
	gint ret = ASPAMD_ERR_OK;
	assassin_parser_t *parser = NULL;
	aspamd_pair_t *pair = NULL;

	ASPAMD_ERR_IF (type != assassin_msg_request && type != assassin_msg_reply,
		       ASPAMD_ERR_PARAM, "unsupported parser type - %i", type);

	parser = g_slice_new (assassin_parser_t);
	ASPAMD_ERR_IF (!parser, ASPAMD_ERR_MEM,"parser allocation failed");
	parser->type = type;
	parser->state = assassin_prs_1_line;
	parser->body_size = 0;
	parser->message = NULL;
	parser->reg_exp = NULL;
	parser->verbose = verbose;
	pair = code_to_str (assassin_msgs, type);
	g_debug ("parser at %p is allocated: type - %s", parser, pair->string);
at_exit:
	if (ret == ASPAMD_ERR_OK)
		*new_parser = parser;
	else
	{
		*new_parser = NULL;
		assassin_parser_free (parser);
	}
	return ret;
}

gint assassin_parser_scan (assassin_parser_t *parser, const gchar *buffer,
			   gint *offset, gint size, gint *completed, gint allocated)
{
	gint ret = ASPAMD_ERR_OK;
	gint state_completed = 1;
	assassin_buffer_t *body = NULL;

	g_assert (parser && buffer && offset && completed);

	/* at least two characters should be available in buffer to
	 * start scanner */
	while (state_completed > 0 && size - *offset >= 2)
	{
		if (parser->verbose)
			g_debug ("parser %p: buffer size - %i, buffer \
offset - %i, parser state - %i", parser, size, *offset, parser->state);
		state_completed = 0;
		switch (parser->state)
		{
		case assassin_prs_1_line:
		{
			ret = parse_1_line (parser, buffer, offset, size, &state_completed);
			if(ret != ASPAMD_ERR_OK)
			{
				parser->state = assassin_prs_error;
				goto at_exit;
			}
			if (state_completed)
			{
				parser->state = assassin_prs_headers;
				if (parser->reg_exp)
				{
					g_regex_unref(parser->reg_exp);
					parser->reg_exp = NULL;
				}
			}
			break;
		}
		case assassin_prs_headers:
		{
			ret = parse_headers (parser, buffer, offset, size,
						      &state_completed);
			if(ret != ASPAMD_ERR_OK)
			{
				parser->state = assassin_prs_error;
				goto at_exit;
			}
			if (state_completed)
			{
				parser->state = assassin_prs_empty_line;
				if (parser->reg_exp)
				{
					g_regex_unref(parser->reg_exp);
					parser->reg_exp = NULL;
				}
			}
			break;
		}
		case assassin_prs_empty_line:
		{
			
			switch (get_line_len (buffer + *offset, size - *offset))
			{
			case 0:
				*offset += 2;
				break;
			default:
				ASPAMD_ERR (ASPAMD_ERR_PARSER,
					    "parser %p: empty line after header is missing",
					    parser);
			}
			
			if (parser->body_size <= 0)
			{
				if (size - *offset)
					g_warning ("parser %p: message %p has no body "
						   "but %i bytes is unprocessed",
						   parser, parser->message,
						   size - *offset);
				state_completed = 0;
				parser->state = assassin_prs_finished;
				*completed = 1;
			}
			else
			{
				state_completed = 1;
				parser->state = assassin_prs_body;
			}
				
			break;
		}
		case assassin_prs_body:
		{
			if (size - *offset < parser->body_size)
				state_completed = 0;
			else
			{
				ret = assassin_buffer_allocate (&body, 0);
				if(ret != ASPAMD_ERR_OK)
				{
					parser->state = assassin_prs_error;
					goto at_exit;
				}
				body->data = (gchar *) buffer;
				body->offset = *offset;
				body->size = parser->body_size + *offset;
				body->allocated = allocated;
				ret = assassin_msg_set_body (parser->message, body);
				if(ret != ASPAMD_ERR_OK)
				{
					parser->state = assassin_prs_error;
					goto at_exit;
				}
				
				*offset += parser->body_size;
				state_completed = 1;
				*completed = 1;
				parser->state = assassin_prs_finished;
			}
			break;
		}
		case assassin_prs_finished:
		{
			state_completed = 0;
			*completed = 1;
			break;
		}
		case assassin_prs_error:
		{
			state_completed = 0;
			*completed = 0;
			ret = ASPAMD_ERR_PARSER;
			break;
		}
		}
	}

at_exit:
	return ret;
}

/** @brief provides parsed SpamAssassin message if parsing is finished
 *
 * @param parser parser
 */

assassin_message_t * assassin_parser_get (assassin_parser_t *parser)
{
	assassin_message_t *ret = NULL;
	if (parser->state == assassin_prs_finished)
	{
		ret = parser->message;
		parser->message = NULL;
	}
	return ret;
}

/** @brief resets parser
 *
 * @param parser parser to be reset
 */

void assassin_parser_reset (assassin_parser_t *parser)
{
	g_assert (parser);

	if (parser->message)
	{
		assassin_msg_free (parser->message);
		parser->message = NULL;
	}

	parser->state = assassin_prs_1_line;

	if (parser->reg_exp)
	{
		g_regex_unref (parser->reg_exp);
		parser->reg_exp = NULL;
	}

	parser->body_size = 0;

	g_debug ("parser %p: reset", parser);
}

/** @brief releases parser and all related resources
 *
 * @param parser parser to be released
 */

void assassin_parser_free (assassin_parser_t *parser)
{
	g_assert (parser);

	g_debug ("parser %p is about to be released", parser);

	assassin_parser_reset (parser);

	g_slice_free1 (sizeof (assassin_parser_t), parser);
}

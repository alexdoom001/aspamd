/* 
 * aspamd - advanced spam daemon 
 *
 */

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <parser.h>
#include <errors.h>

enum assassin_prs_1line
{
	assassin_1l_command = 1,
	assassin_1l_client,
	assassin_1l_major,
	assassin_1l_minor,
	assassin_1l_finished
};

static struct
{
	gchar *str;
	gint command;
}str_to_command[] = {
	{"CHECK", assassin_cmd_check},
	{"SYMBOLS", assassin_cmd_symbols},
	{"REPORT", assassin_cmd_report},
	{"REPORT_IFSPAM", assassin_cmd_report_ifspam},
	{"SKIP", assassin_cmd_skip},
	{"PING", assassin_cmd_ping},
	{"PROCESS", assassin_cmd_process},
	{"TELL", assassin_cmd_tell},
	{"HEADERS", assassin_cmd_headers }
};

static struct
{
	gchar *str;
	gint header;
}str_to_header[] = {
	{"content-length", assassin_hdr_content_length},
	{"spam", assassin_hdr_spam},
	{"user", assassin_hdr_user},
	{"compress", assassin_hdr_compress},
	{"message-class", assassin_hdr_message_class},
	{"remove", assassin_hdr_remove},
	{"set", assassin_hdr_set},
	{"didset", assassin_hdr_did_set},
	{"didremove", assassin_hdr_did_remove}
};

static gint assassin_parse_1_line_values(assassin_parser_t *parser, GMatchInfo *match_info,
					 const gchar *buffer, gint offset)
{
	gint ret = ASPAMD_ERR_OK;
	gchar *token = NULL;
	gint state = assassin_1l_command, start, end, i;
	/* extracted */
	gint command = -1, major, minor;
	gchar *client = NULL;

	while (state != assassin_1l_finished)
	{
		switch (state)
		{
		case assassin_1l_command:
		{
			if(!g_match_info_fetch_pos (match_info, state, &start, &end))
			{
				g_critical ("token fetch failed");
				ret = ASPAMD_ERR_PARSER;
				goto at_exit;
			}
			token = (gchar *) buffer + offset + start;

			for (i = 0; i < sizeof (str_to_command)/
				     sizeof (str_to_command[0]);
			     i++)
			{
				if (g_ascii_strncasecmp (str_to_command[i].str, token,
							 end - start) == 0)
				{
					command = str_to_command[i].command;
					break;
				}
			}
			if (command == -1)
			{
				token = g_match_info_fetch (match_info, state);
				g_critical ("unknown command: %s", token);
				g_free (token);
				ret = ASPAMD_ERR_PARSER;
				goto at_exit;
			}
			state = assassin_1l_client;
			break;
		}
		case assassin_1l_client:
		{
			client = g_match_info_fetch (match_info, state);
			state = assassin_1l_major;
			break;
		}
		case assassin_1l_major:
		{
			token = g_match_info_fetch (match_info, state);
			major = atoi (token);
			g_free (token);
			state = assassin_1l_minor;
			break;
		}
		case assassin_1l_minor:
		{
			token = g_match_info_fetch (match_info, state);
			minor = atoi (token);
			g_free (token);
			state = assassin_1l_finished;
			break;
		}
		}
	}

	ret = assassin_msg_allocate (&parser->message, parser->type, command, major, minor);
	ASPAMD_ERR_CHECK (ret);
	parser->message->client = client;

at_exit:
	if (ret != ASPAMD_ERR_OK)
	{
		if (client)
			g_free (client);
	}
	return ret;
}

static gint assassin_parse_1_line (assassin_parser_t *parser, const gchar *buffer,
				   gint *offset, gint size, gint *completed)
{
	gint ret = ASPAMD_ERR_OK;
	GMatchInfo *match_info = NULL;
	GError *gerr = NULL;
	gint start, end;
	gboolean match;
	gchar *sub = NULL, *clean_sub;

	g_assert (parser && buffer && offset);

	if (!parser->reg_exp)
	{
		if (parser->type == assassin_msg_request)
		{
			parser->reg_exp =  g_regex_new (
				"^([[:alpha:]]+)\\s+([[:alpha:]]+)/(\\d+)\\.(\\d+)\\r\\n",
				G_REGEX_OPTIMIZE,
				G_REGEX_MATCH_ANCHORED | G_REGEX_MATCH_PARTIAL, &gerr);
			if (gerr)
			{
				g_critical ("regular expression error: %s", gerr->message);
				ret = ASPAMD_ERR_PARSER;
				goto at_exit;
			}
		}

	}

	match = g_regex_match_full (parser->reg_exp, buffer, size, *offset,
				    0, &match_info, &gerr);
	if (gerr)
	{
		g_critical ("header 1 line parsing error: %s", gerr->message);
		ret = ASPAMD_ERR_PARSER;
		goto at_exit;
	}

	if(!match)
	{
		if (g_match_info_is_partial_match (match_info))
			goto at_exit;
		sub = g_strndup (buffer + *offset, size - *offset);
		if (sub)
			clean_sub = g_strescape (sub, NULL);
		g_critical ("header 1 line parsing failed at offset %i, string: %s",
			    *offset, clean_sub);
		if (sub) g_free (sub);
		if (clean_sub) g_free (clean_sub);
		ret = ASPAMD_ERR_PARSER;
		goto at_exit;
	}

	if (g_match_info_matches (match_info))
	{
		ret = assassin_parse_1_line_values (parser, match_info, buffer, *offset);
		ASPAMD_ERR_CHECK (ret);
		g_assert (g_match_info_fetch_pos (match_info, 0, &start, &end));
		*offset += end - start;
		*completed = 1;
	}
at_exit:
	if (match_info)
		g_match_info_free (match_info);
	if (ret != ASPAMD_ERR_OK)
		*completed = 0;
	return ret;
}

static gint assassin_process_spam_header(assassin_parser_t *parser, gchar* value)
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
		G_REGEX_OPTIMIZE,
		G_REGEX_MATCH_ANCHORED, &gerr);
	if (gerr)
	{
		g_critical ("regular expression error: %s", gerr->message);
		ret = ASPAMD_ERR_PARSER;
		goto at_exit;
	}

	match = g_regex_match_full (reg_exp, value, -1, 0,
				    0, &match_info, &gerr);

	if (gerr)
	{
		g_critical ("`spam' header parsing error: %s", gerr->message);
		ret = ASPAMD_ERR_PARSER;
		goto at_exit;
	}

	if(!match)
	{
		g_critical ("`spam' header parsing failed, buffer - %s",
			value);
		ret = ASPAMD_ERR_PARSER;
		goto at_exit;
	}

	if (g_match_info_matches (match_info))
	{
		token = g_match_info_fetch (match_info, 1);
		g_assert (token);
		if (g_ascii_strcasecmp (token, "true") == 0)
			spam = TRUE;
		else if (g_ascii_strcasecmp (token, "false") == 0)
			spam = FALSE;
		else
		{
			g_critical ("`spam' header qualifier `%s' is unknown", token);
			ret = ASPAMD_ERR_PARSER;
			goto at_exit;
		}
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
	if (match_info)
		g_match_info_free (match_info);
	if (reg_exp)
		g_regex_unref (reg_exp);
	if (token)
		g_free (token);
	return ret;
}

static gint assassin_process_header (assassin_parser_t *parser, gchar *header, gchar* value)
{
	gint ret = ASPAMD_ERR_OK, i, header_bin = -1;

	g_assert (parser && header && value);

	for (i = 0; i < sizeof (str_to_header)/
		     sizeof (str_to_header[0]);
	     i++)
	{
		if (g_ascii_strcasecmp (str_to_header[i].str, header) == 0)
		{
			header_bin = str_to_header[i].header;
			break;
		}
	}
	if (header_bin == -1)
	{
		g_critical ("header `%s' is not supported by the current protocol version",
			    header);
		ret = ASPAMD_ERR_PARSER;
		goto at_exit;
	}

	switch (header_bin)
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
		ret = assassin_process_spam_header (parser, value);
		ASPAMD_ERR_CHECK (ret);
		break;
	}
	default:
		g_critical ("header `%s' is not supported by the parser, omitting", header);
	}

at_exit:
	g_free (header);
	g_free (value);

	return ret;
}

static gint assassin_parse_headers (assassin_parser_t *parser, const gchar *buffer,
				    gint *offset, gint size, gint *completed)
{
	gint ret = ASPAMD_ERR_OK;
	GMatchInfo *match_info = NULL;
	GError *gerr = NULL;
	gint start, end;
	gboolean match;
	gchar *sub = NULL, *clean_sub = NULL;

	g_assert (parser && buffer && offset);

	if (strncmp (buffer + *offset, "\r\n",
		     MIN(size - *offset, 2)) == 0)
	{
		g_debug ("no more headers");
		*completed = 1;
		goto at_exit;
	}

	if (!parser->reg_exp)
	{
		parser->reg_exp =  g_regex_new (
			"([[:alnum:]-]+)\\s*:\\s*(.+)\\r\\n",
			G_REGEX_OPTIMIZE | G_REGEX_MULTILINE,
			G_REGEX_MATCH_ANCHORED | G_REGEX_MATCH_PARTIAL, &gerr);
		if (gerr)
		{
			g_critical ("regular expression error: %s", gerr->message);
			ret = ASPAMD_ERR_PARSER;
			goto at_exit;
		}
	}

	match = g_regex_match_full (parser->reg_exp, buffer, size, *offset,
				    0, &match_info, &gerr);

	if (gerr)
	{
		g_critical ("header parsing error: %s", gerr->message);
		ret = ASPAMD_ERR_PARSER;
		goto at_exit;
	}

	if(!match)
	{
		if (g_match_info_is_partial_match (match_info))
			goto at_exit;

		sub = g_strndup (buffer + *offset, size - *offset);
		if (sub)
			clean_sub = g_strescape (sub, NULL);
		g_critical ("header parsing failed at offset %i, string: %s",
			    *offset, clean_sub);
		if (sub) g_free (sub);
		if (clean_sub) g_free (clean_sub);
		ret = ASPAMD_ERR_PARSER;
		goto at_exit;
	}
	

	while (g_match_info_matches (match_info))
	{
		ret = assassin_process_header (parser, 
					       g_match_info_fetch (match_info, 1),
					       g_match_info_fetch (match_info, 2));
		ASPAMD_ERR_CHECK (ret);

		g_assert (g_match_info_fetch_pos (match_info, 0, &start, &end));
		*offset += end - start;

		if (size - 1 - *offset > 0)
		{
			match = g_match_info_next (match_info, &gerr);
			if (gerr)
			{
				g_critical ("header parsing error: %s", gerr->message);
				ret = ASPAMD_ERR_PARSER;
				goto at_exit;
			}
			if (!match)
			{
				if (g_match_info_is_partial_match (match_info))
					goto at_exit;
				break;
			}
		}
		else
			goto at_exit;
	}
	*completed = 1;

at_exit:
	if (match_info)
		g_match_info_free (match_info);
	if (ret != ASPAMD_ERR_OK)
		*completed = 0;
	return ret;
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

	parser = g_slice_new (assassin_parser_t);
	if (!parser)
	{
		g_critical ("memory allocation failed");
		ret = ASPAMD_ERR_MEM;
		goto at_exit;
	}
	parser->type = type;
	parser->state = assassin_prs_1_line;
	parser->body_size = 0;
	parser->message = NULL;
	parser->reg_exp = NULL;
	parser->verbose = verbose;
	g_debug ("new parser %p is created", parser);
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
			   gint *offset, gint size, gint *completed, gint auto_free)
{
	gint ret = ASPAMD_ERR_OK;
	gint state_completed = 1;

	g_assert (parser && buffer && offset && completed);

	/* at least two characters should be available in buffer to
	 * start scanner */
	while (state_completed > 0 && size - *offset >= 2)
	{
		if (parser->verbose)
			g_debug ("buffer size - %i, buffer offset - %i, parser state - %i",
				 size, *offset, parser->state);
		state_completed = 0;
		switch (parser->state)
		{
		case assassin_prs_1_line:
		{
			ret = assassin_parse_1_line (parser, buffer, offset, size,
						     &state_completed);
			if(ret != ASPAMD_ERR_OK)
			{
				parser->state = assassin_prs_error;
				goto at_exit;
			}
			if (state_completed)
			{
				parser->state = assassin_prs_headers;
				g_regex_unref(parser->reg_exp);
				parser->reg_exp = NULL;
			}
			break;
		}
		case assassin_prs_headers:
		{
			ret = assassin_parse_headers (parser, buffer, offset, size,
						      &state_completed);
			if(ret != ASPAMD_ERR_OK)
			{
				parser->state = assassin_prs_error;
				goto at_exit;
			}
			if (state_completed)
			{
				parser->state = assassin_prs_empty_line;
				g_regex_unref(parser->reg_exp);
				parser->reg_exp = NULL;
			}
			break;
		}
		case assassin_prs_empty_line:
		{
			if (strncmp (buffer + *offset, "\r\n",
				     MIN(size - *offset, 2)) != 0)
			{
				g_critical ("empty line after header is missing");
				ret = ASPAMD_ERR_PARSER;
				goto at_exit;
			}
			*offset += 2;
			
			if (parser->body_size <= 0)
			{
				if (size - *offset)
					g_warning ("%p message has no body but some data\
 in the buffer is still available",
						   parser->message);
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
				ret = assassin_msg_add_body (parser->message,
							     (gchar *) buffer, *offset,
							     parser->body_size, auto_free);

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
		assassin_msg_free (parser->message);

	parser->state = assassin_prs_1_line;

	if (parser->reg_exp)
	{
		g_regex_unref (parser->reg_exp);
		parser->reg_exp = NULL;
	}

	parser->body_size = 0;

	g_debug ("parser %p is reset", parser);
}

/** @brief releases parser and all related resources
 *
 * @param parser parser to be released
 */

void assassin_parser_free (assassin_parser_t *parser)
{
	g_assert (parser);

	assassin_parser_reset (parser);

	g_slice_free1 (sizeof (assassin_parser_t), parser);
}

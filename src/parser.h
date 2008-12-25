/* 
 * aspamd - advanced spam daemon 
 *
 */

/*! \file parser.h
 *  \brief SpamAssassin message parser */

#ifndef _ASSASSIN_PARSER_
#define _ASSASSIN_PARSER_

#include <assassin.h>

/** parser data */
struct assassin_parser
{
	gint	state,
		/*!< internal variable describing parser state */
		type,
		/*!< internal variable describing parser type, take a
		 * look at #assassin_message_type for details */
		body_size;
		/*!< size of the message body */
	gboolean verbose;
	/*!< be more talkative */
	assassin_message_t *message;
	/*!< parsed message */
	GRegex *reg_exp;
};

typedef struct assassin_parser assassin_parser_t;

enum assassin_prs_state
{
	assassin_prs_1_line,
	assassin_prs_headers,
	assassin_prs_empty_line,
	assassin_prs_body,
	assassin_prs_finished,
	assassin_prs_error
};

gint assassin_parser_allocate (assassin_parser_t **new_parser, gint type, gint verbose);
gint assassin_parser_scan (assassin_parser_t *parser, const gchar *buffer, gint *offset,
			   gint size, gint *completed, gint allocated);
void assassin_parser_reset (assassin_parser_t *parser);
assassin_message_t * assassin_parser_get (assassin_parser_t *parser);
void assassin_parser_free (assassin_parser_t *parser);

#endif

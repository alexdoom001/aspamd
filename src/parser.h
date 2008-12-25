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
	assassin_message_t *message;
	/*!< parsed message */
	GRegex *reg_exp;
};

typedef struct assassin_parser assassin_parser_t;

gint assassin_parser_allocate (assassin_parser_t **new_parser, gint type);
gint assassin_parser_scan (assassin_parser_t *parser, const gchar *buffer, gint *offset,
			   gint size, gint *completed, gint auto_free);
void assassin_parser_reset (assassin_parser_t *parser);
assassin_message_t * assassin_parser_get (assassin_parser_t *parser);
void assassin_parser_free (assassin_parser_t *parser);

#endif

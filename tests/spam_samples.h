/* 
 * SpamAssassin message parser tests
 *
 */

#ifndef _TEST_SAMPLES_
#define _TEST_SAMPLES_

enum
{
	message_spam,
	message_not_spam,
	message_ping,
	message_error,
	message_error_no_reply
};

struct sample_message
{
	gint type;
	int rating;
	const char *body;
};

typedef struct sample_message sample_message_t;

extern sample_message_t messages[];

extern sample_message_t buggy_messages[];

#endif

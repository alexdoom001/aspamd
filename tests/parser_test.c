/* 
 * SpamAssassin message parser tests
 *
 */

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <assassin.h>
#include <logging.h>
#include <errors.h>
#include <parser.h>

/*-----------------------------------------------------------------------------*/

gint message_to_string_test_1 ();
gint message_to_string_test_2 ();
gint string_to_message_test_1 ();
gint string_to_message_test_2 ();
gint string_to_message_test_3 ();
gint string_to_message_test_4 ();

assassin_parser_t *parser;

typedef gint (* test_t) ();

const struct
{
	test_t test;
	const gchar *description;
}tests[] = {
	{&message_to_string_test_1, "trivial message serialization test"},
	{&message_to_string_test_2, "message serialization in case of buffer overflow"},
	{&string_to_message_test_1, "trivial parser test"},
	{&string_to_message_test_2, "growing buffer test"},
	{&string_to_message_test_3, "bad patterns test"},
	{&string_to_message_test_4, "body-less messages test"},
	{0,0}
};

/*-----------------------------------------------------------------------------*/

const gchar msg_to_string_1_output[] =
"SPAMD/1.4 64 EX_USAGE\r\nuser: pavels\r\ncontent-length: 20\r\nspam: true ; 10 / 2\r\n\r\n\
--processed message ";

gint message_to_string_test_1 ()
{
	gint	ret = ASPAMD_ERR_OK,
		filling = 0,
		pos;
	assassin_message_t *message = NULL;
	const gchar *content = "--processed message ";
	gchar *buffer;
	GVariant *dup_header;

	ret = assassin_msg_allocate (&message, assassin_msg_response, assassin_cmd_process,
				     1, 4);
	ASPAMD_ERR_CHECK (ret);
	message->error = assassin_ex_usage;
	ret = assassin_msg_add_header (message, assassin_hdr_user,
				       g_variant_new_string ("pavels"));
	ASPAMD_ERR_CHECK (ret);
	ret = assassin_msg_add_header (message, assassin_hdr_content_length,
				       g_variant_new_int32 (strlen (content)));
	ASPAMD_ERR_CHECK (ret);

	dup_header = g_variant_new_int32 (0xd34dbeaf);
	ret = assassin_msg_add_header (message, assassin_hdr_content_length,
				       dup_header);
	if (ret != ASPAMD_ERR_MSG)
	{
		g_critical ("%s test failed, duplicating header is not rejected", __FUNCTION__);
		ret = ASPAMD_ERR_MSG;
		goto at_exit;
	}
	ret = ASPAMD_ERR_OK;
	g_variant_unref (dup_header);

	ret = assassin_msg_add_header (message, assassin_hdr_spam,
				       g_variant_new ("(bii)", TRUE, 10, 2));
	ASPAMD_ERR_CHECK (ret);

	ret = assassin_msg_add_body (message, (gpointer) content, 0, strlen (content),
				     FALSE);

	ret = assassin_msg_printf (message, (gpointer *)&buffer, &filling);
	ASPAMD_ERR_CHECK (ret);

	if (strlen (msg_to_string_1_output) != filling)
	{
		g_critical ("%s test failed, output buffer filling is incorrect",
			    __FUNCTION__);
		ret = ASPAMD_ERR_MSG;
		goto at_exit;
	}

	pos = g_ascii_strncasecmp (msg_to_string_1_output, buffer, filling);

	if (pos != 0)
	{
		g_critical ("%s test failed, messages differ at %i", __FUNCTION__, pos);
		ret = ASPAMD_ERR_ERR;
		goto at_exit;
	}

at_exit:
	if (message)
		assassin_msg_free (message);
	if (buffer)
		g_free(buffer);
	return ret;
}

/*-----------------------------------------------------------------------------*/

gint message_to_string_test_2 ()
{
	gint	ret = ASPAMD_ERR_OK,
		filling = 0;
	assassin_message_t *message = NULL;
	const gchar *content = "--processed message ";
	gchar *buffer;
	GVariant *dup_header;

	ret = assassin_msg_allocate (&message, assassin_msg_response, assassin_cmd_process,
				     1, 4);
	ASPAMD_ERR_CHECK (ret);
	message->error = assassin_ex_usage;
	ret = assassin_msg_add_header (message, assassin_hdr_user,
				       g_variant_new_string ("very_long_value:\
very_long_value:very_long_value:very_long_value:very_long_value:very_long_value:\
very_long_value:very_long_value:very_long_value:very_long_value:very_long_value:\
very_long_value"));
	ASPAMD_ERR_CHECK (ret);
	ret = assassin_msg_add_header (message, assassin_hdr_content_length,
				       g_variant_new_int32 (strlen (content)));
	ASPAMD_ERR_CHECK (ret);

	dup_header = g_variant_new_int32 (0xd34dbeaf);
	ret = assassin_msg_add_header (message, assassin_hdr_content_length,
				       dup_header);
	if (ret != ASPAMD_ERR_MSG)
	{
		g_critical ("%s test failed, duplicating header is not rejected", __FUNCTION__);
		ret = ASPAMD_ERR_MSG;
		goto at_exit;
	}
	ret = ASPAMD_ERR_OK;
	g_variant_unref (dup_header);

	ret = assassin_msg_add_header (message, assassin_hdr_spam,
				       g_variant_new ("(bii)", TRUE, 10, 2));
	ASPAMD_ERR_CHECK (ret);

	ret = assassin_msg_add_body (message, (gpointer) content, 0, strlen (content),
				     FALSE);

	ret = assassin_msg_printf (message, (gpointer *)&buffer, &filling);

	if (ret == ASPAMD_ERR_OK)
	{
		g_critical ("%s test failed", __FUNCTION__);
		ret = ASPAMD_ERR_MSG;
		goto at_exit;
	}
	ret = ASPAMD_ERR_OK;

at_exit:
	if (message)
		assassin_msg_free (message);
	if (buffer)
		g_free(buffer);
	return ret;
}

/*-----------------------------------------------------------------------------*/

const gchar str_to_msg_1_input[] =
{"PROCESS SPAMC/1.2\r\nuser: pavels\r\ncontent-length: 20\r\nspam: true ; 10 / 2\r\n\r\n\
--processed message|"};

gint string_to_message_test_1 ()
{
	gint ret = ASPAMD_ERR_OK;
	gint offset = 0, completed = 0;

	assassin_parser_reset (parser);

	ret = assassin_parser_scan (parser, str_to_msg_1_input, &offset,
				    strlen (str_to_msg_1_input), &completed, FALSE);
	ASPAMD_ERR_CHECK (ret);
	if (offset != strlen (str_to_msg_1_input))
	{
		g_critical ("%s test failed, buffer offset is incorrect",
			    __FUNCTION__);
		ret = ASPAMD_ERR_PARSER;
		goto at_exit;
	}
	if (!completed)
	{
		g_critical ("%s test failed, completion status is incorrect",
			    __FUNCTION__);
		ret = ASPAMD_ERR_PARSER;
		goto at_exit;
	}

at_exit:
	return ret;
}

/*-----------------------------------------------------------------------------*/

gint string_to_message_test_2 ()
{
	gint ret = ASPAMD_ERR_OK;
	gint	offset = 0,
		completed = 0,
		i = 0,
		buffer_size = 0;
	assassin_message_t *msg = NULL;
	gchar *body = NULL;

	assassin_parser_reset (parser);

	for (i = 0, buffer_size = 1; i < strlen (str_to_msg_1_input); i++, buffer_size++)
	{
		ret = assassin_parser_scan (parser, str_to_msg_1_input, &offset,
					    buffer_size,
					    &completed, FALSE);
		ASPAMD_ERR_CHECK (ret);
		if (completed)
			break;
	}

	if (offset != strlen (str_to_msg_1_input))
	{
		g_critical ("%s test failed, buffer offset is incorrect",
			    __FUNCTION__);
		ret = ASPAMD_ERR_PARSER;
		goto at_exit;
	}

	if (!completed)
	{
		g_critical ("%s test failed, completion status is incorrect",
			    __FUNCTION__);
		ret = ASPAMD_ERR_PARSER;
		goto at_exit;
	}

	msg = assassin_parser_get (parser);
	if (!msg)
	{
		g_critical ("%s test failed, no message returned by parser",
			    __FUNCTION__);
		ret = ASPAMD_ERR_PARSER;
		goto at_exit;
	}

	body = g_strndup (msg->content.buffer + msg->content.offset,
			  msg->content.size);
	g_debug ("body - %s", body);
at_exit:
	if (body)
		g_free (body);
	if (msg)
		assassin_msg_free (msg);
	return ret;
}

/*-----------------------------------------------------------------------------*/

gchar *bad_patterns[] = {
"PROC1-ESS SPAMC/1.2\r\nuser: pavels\r\ncontent-length: 20\r\nspam: true ; 10 / 2\r\n\r\n\
--processed message|",
"PROCESS SP**AMC/1.2\r\nuser: pavels\r\ncontent-length: 20\r\nspam: true ; 10 / 2\r\n\r\n\
--processed message|",
"PROCESS SPAMC/+a.1\r\nuser: pavels\r\ncontent-length: 20\r\nspam: true ; 10 / 2\r\n\r\n\
--processed message|",
"PROCESS SPAMC/1.1\r\nus=er: pavels\r\ncontent-length: 20\r\nspam: true ; 10 / 2\r\n\r\n\
--processed message|"
"PROCESS SPAMC/1.1\r\nuser:\r\ncontent-length: 20\r\nspam: true ; 10 / 2\r\n\r\n\
--processed message|"};

gint string_to_message_test_3 ()
{
	gint ret = ASPAMD_ERR_OK;
	gint offset = 0, completed = 0, i;


	for (i = 0; i < sizeof (bad_patterns) / sizeof (bad_patterns[0]); i++)
	{
		offset = 0;
		completed = 0;
		ret = ASPAMD_ERR_OK;

		assassin_parser_reset (parser);

		ret = assassin_parser_scan (parser, bad_patterns[i], &offset,
					    strlen (bad_patterns[i]), &completed,
					    FALSE);

		if (ret == ASPAMD_ERR_OK)
		{
			ret = ASPAMD_ERR_PARSER;
			goto at_exit;
		}

		if (completed)
		{
			g_critical ("completion status is incorrect");
			ret = ASPAMD_ERR_PARSER;
			goto at_exit;
		}

		if (offset >= strlen (bad_patterns[i]) - 1)
		{
			g_critical ("buffer offset is incorrect");
			ret = ASPAMD_ERR_PARSER;
			goto at_exit;
		}
	}
	ret = ASPAMD_ERR_OK;

at_exit:
	return ret;
}

/*-----------------------------------------------------------------------------*/

const gchar str_to_msg_4_input[] =
{"TELL SPAMC/1.4\r\nMessage-class: spam\r\nSet: local\r\n\r\n"};

gint string_to_message_test_4 ()
{
	gint ret = ASPAMD_ERR_OK;
	gint offset = 0, completed = 0;

	assassin_parser_reset (parser);

	ret = assassin_parser_scan (parser, str_to_msg_4_input, &offset,
				    strlen (str_to_msg_4_input), &completed, FALSE);
	ASPAMD_ERR_CHECK (ret);
	if (offset != strlen (str_to_msg_4_input))
	{
		g_critical ("%s test failed, buffer offset is incorrect",
			    __FUNCTION__);
		ret = ASPAMD_ERR_PARSER;
		goto at_exit;
	}
	if (!completed)
	{
		g_critical ("%s test failed, completion status is incorrect",
			    __FUNCTION__);
		ret = ASPAMD_ERR_PARSER;
		goto at_exit;
	}

at_exit:
	return ret;
}

/*-----------------------------------------------------------------------------*/

int main (int argc, char *argv[])
{
	gint ret = ASPAMD_ERR_OK;
	aspamd_log_data_t log;
	gint i;

	srandom (time (NULL));

	ret = aspamd_logger_early_configure (&log);
	ASPAMD_ERR_CHECK (ret);

	ret = assassin_parser_allocate (&parser, assassin_msg_request, 0);
	ASPAMD_ERR_CHECK (ret);

	for (i = 0; tests[i].test; i++)
	{
		ret = tests[i].test ();
		if (ret == ASPAMD_ERR_OK)
			g_message ("  %s - PASSED", tests[i].description);
		else
			g_message ("  %s - FAILED", tests[i].description);
	}

at_exit:
	if (parser)
		assassin_parser_free (parser);
	if (ret == ASPAMD_ERR_OK)
	{
		g_message ("-------------------------------------");
		g_message (" ");
		g_message (" ALL PARSER TESTS ARE PASSED SUCCESSFULLY");
	}
	return ret;
}

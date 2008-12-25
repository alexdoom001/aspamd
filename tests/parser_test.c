/* 
 * SpamAssassin message parser tests
 *
 */

#include <string.h>
#include <glib.h>
#include <assassin.h>
#include <logging.h>
#include <errors.h>
#include <parser.h>

gchar ref_ouput_1[] =
{"SPAMD/1.4 64 EX_USAGE\r\nuser: pavels\r\ncontent-length: 20\r\nspam: true ; 10 / 2\r\n\r\n\
--processed message "};

gint message_to_string_test_1 ()
{
	gint	ret = ASPAMD_ERR_OK,
		filling = 0,
		pos;
	assassin_message_t *message = NULL;
	gchar	*buffer,
		*content = "--processed message ";
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
		g_critical ("duplicating header is not rejected");
		goto at_exit;
	}
	ret = ASPAMD_ERR_OK;
	g_variant_unref (dup_header);

	ret = assassin_msg_add_header (message, assassin_hdr_spam,
				       g_variant_new ("(bii)", TRUE, 10, 2));
	ASPAMD_ERR_CHECK (ret);

	ret = assassin_msg_add_body (message, content, 0, strlen (content), FALSE);

	ret = assassin_msg_printf (message, (gpointer *)&buffer, &filling);
	ASPAMD_ERR_CHECK (ret);

	pos = strncmp (ref_ouput_1, buffer, filling);

	printf ("\n%s\n\n", buffer);

	if (pos != 0)
	{
		g_critical ("%s test failed, messages differ at %i\n", __FUNCTION__, pos);
		ret = ASPAMD_ERR_ERR;
		goto at_exit;
	}

	if (strlen (ref_ouput_1) != filling)
	{
		g_critical ("%s test failed, output buffer filling %i bytes is not correct",
			    __FUNCTION__, filling);
		ret = ASPAMD_ERR_ERR;
		goto at_exit;
	}

at_exit:
	if (message)
		assassin_msg_free (message);
	if (buffer)
		g_free(buffer);
	if (ret == ASPAMD_ERR_OK)
		g_message ("%s passed\n", __FUNCTION__);
	return ret;
}

gchar ref_input_1[] =
{"PROCESS SPAMC/1.2\r\nuser: pavels\r\ncontent-length: 20\r\nspam: true ; 10 / 2\r\n\r\n\
--processed message "};

gint string_to_message_test_1 ()
{
	gint ret = ASPAMD_ERR_OK;
	assassin_parser_t *parser;
	gint offset = 0, completed = 1;

	ret = assassin_parser_allocate (&parser, assassin_msg_request);
	ASPAMD_ERR_CHECK (ret);

	ret = assassin_parser_scan (parser, ref_input_1, &offset,
				    strlen (ref_input_1), &completed, FALSE);
	ASPAMD_ERR_CHECK (ret);
	g_assert (offset <= strlen (ref_input_1));

at_exit:
	if (parser)
		assassin_parser_free (parser);
	if (ret == ASPAMD_ERR_OK)
		g_message ("%s passed\n", __FUNCTION__);

	return ret;
}

int main (int argc, char *argv[])
{
	gint ret = ASPAMD_ERR_OK;
	aspamd_log_data_t log;

	ret = aspamd_logger_early_configure (&log);
	ASPAMD_ERR_CHECK (ret);

	ret = message_to_string_test_1 ();
	ASPAMD_ERR_CHECK (ret);

	ret = string_to_message_test_1 ();
	ASPAMD_ERR_CHECK (ret);

at_exit:
	if (ret == ASPAMD_ERR_OK)
	{
		g_message ("-------------------------------------");
		g_message (" ");
		g_message (" ALL PARSER TESTS ARE PASSED SUCCESSFULLY");
	}
	return ret;
}

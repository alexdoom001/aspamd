/* 
 * aspamd - advanced spam daemon 
 *
 */

#include <glib.h>
#include <assassin.h>
#include <pairs.h>

aspamd_pair_t assassin_cmds[] = {
	{assassin_cmd_check, "CHECK"},
	{assassin_cmd_symbols, "SYMBOLS"},
	{assassin_cmd_report, "REPORT"},
	{assassin_cmd_report_ifspam, "REPORT_IFSPAM"},
	{assassin_cmd_skip, "SKIP"},
	{assassin_cmd_ping, "PING"},
	{assassin_cmd_process, "PROCESS"},
	{assassin_cmd_tell, "TELL"},
	{assassin_cmd_headers, "HEADERS"},
	{0, NULL}
};

aspamd_pair_t assassin_hdrs[] = {
	{assassin_hdr_content_length, "content-length"},
	{assassin_hdr_spam, "spam"},
	{assassin_hdr_user, "user"},
	{assassin_hdr_compress, "compress"},
	{assassin_hdr_message_class, "message-class"},
	{assassin_hdr_remove, "remove"},
	{assassin_hdr_set, "set"},
	{assassin_hdr_did_set, "didset"},
	{assassin_hdr_did_remove, "didremove"},
	{assassin_hdr_client_address, "client-address"},
	{assassin_hdr_helo_name, "helo-name"},
	{assassin_hdr_mail_from, "mail-from"},
	{assassin_hdr_rcpt_to, "rcpt-to"},
	{assassin_hdr_quarantine, "quarantine"},
	{0, NULL}
};

aspamd_pair_t assassin_errs[] =
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
	{assassin_ex_timeout, "EX_TIMEOUT"},
	{0, NULL}
};

aspamd_pair_t assassin_msgs[] = {
	{assassin_msg_request, "request"},
	{assassin_msg_reply, "reply"},
	{0, NULL}};

aspamd_pair_t *code_to_str (aspamd_pair_t *pairs, gint code)
{
	static aspamd_pair_t stat_pair = {-1, ""};
	aspamd_pair_t *ret = &stat_pair;
	gint i;
	stat_pair.code = code;

	for (i = 0; pairs[i].string; i++)
	{
		if (pairs[i].code == code)
		{
			ret = &pairs[i];
			break;
		}
	}

	return ret;
}

aspamd_pair_t *str_to_code (aspamd_pair_t *pairs, const gchar *string)
{
	static aspamd_pair_t stat_pair = {-1, ""};
	aspamd_pair_t *ret = &stat_pair;
	gint i;

	for (i = 0; pairs[i].string; i++)
	{
		if (g_ascii_strcasecmp(pairs[i].string, string) == 0)
		{
			ret = &pairs[i];
			break;
		}
	}

	return ret;
}

aspamd_pair_t *strn_to_code (aspamd_pair_t *pairs, const gchar *string, gint n)
{
	static aspamd_pair_t stat_pair = {-1, ""};
	aspamd_pair_t *ret = &stat_pair;
	gint i;

	for (i = 0; pairs[i].string; i++)
	{
		if (g_ascii_strncasecmp(pairs[i].string, string, n) == 0)
		{
			ret = &pairs[i];
			break;
		}
	}

	return ret;
}

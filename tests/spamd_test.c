/* 
 * SpamAssassin message parser tests
 *
 */

#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <glib.h>
#include <errors.h>
#include <logging.h>
#include <assassin.h>
#include <parser.h>
#include <spamd_test.h>
#include <spam_samples.h>
#include <config.h>

aspamd_log_data_t logger;

const gchar *default_server_ip = TEST_DEFAULT_IP,
	*default_sock_path =TEST_DEFAULT_SOCK_PATH;

gchar *server_ip = NULL,
	*sock_path = NULL;

gint	server_port = TEST_DEFAULT_PORT,
	client_rate = TEST_CLNT_RATE_SLOW,
	client_manner = TEST_CLNT_CLEVER,
	running = 0;

assassin_parser_t *parser = NULL;

gchar buffer[TEST_BUFFER_SIZE];
gint buffer_filling;
struct stat
{
	gint pings, msgs, err_msgs, refused;
}stats;

void random_delay (gint client_rate);

gint parse_com_line (int argc, char *argv[])
{
	gint err = ASPAMD_ERR_OK;
	GError *gerr = NULL;
	GOptionContext *opt_context = NULL;

	GOptionEntry entries[] = 
		{
			{ "rate", 'r', 0, G_OPTION_ARG_INT,
			  &client_rate,
			  "request generation rate", NULL},
			{ "manner", 'm', 0, G_OPTION_ARG_INT,
			  &client_manner,
			  "manner to work", NULL},
			{ "port", 'p', 0, G_OPTION_ARG_INT,
			  &server_port,
			  "server port", NULL},
			{ "ip", 'i', 0, G_OPTION_ARG_STRING,
			  &server_ip,
			  "server ip", NULL},
			{ "unix", 'u', 0, G_OPTION_ARG_STRING,
			  &sock_path,
			  "UNIX socket path", NULL},
			{ NULL }
		};

	opt_context = g_option_context_new ("- spamd test utility");
	if (!opt_context)
	{
		g_critical ("memory allocation failed");
		err = ASPAMD_ERR_MEM;
		goto at_exit;
	}
	g_option_context_add_main_entries (opt_context, entries, NULL);
	if (!g_option_context_parse (opt_context, &argc, &argv, &gerr))
	{                
		g_critical ("option parsing failed: %s", gerr->message);
		err = ASPAMD_ERR_CM_LINE;
		goto at_exit;
	}
	if (!server_ip && !sock_path)
		sock_path = (char *) default_sock_path;
	if (client_rate < 0 || client_rate > TEST_CLNT_RATE_SLOW)
		client_rate = TEST_CLNT_RATE_MEDIUM;
	if (client_manner < 0 || client_manner > TEST_CLNT_BUGGY)
		client_manner = TEST_CLNT_CLEVER;
		
	g_debug ("command line is parsed successfully");
	g_message ("server - %s:%i", server_ip, server_port);
	g_message ("manner - %i, rate - %i", client_manner, client_rate);
at_exit:
	if (opt_context)
		g_option_context_free (opt_context);
	return err;
}

gint sock_open_connect (gint *new_sock, const gchar *ip_path, gint port)
{
	gint ret = ASPAMD_ERR_OK, sock = -1;
	struct sockaddr_in sock_addr_in;
	struct sockaddr_un sock_addr_un;
	int cur_options;

	g_assert (new_sock);

	if (sock_path)
	{
		sock = socket (AF_UNIX, SOCK_STREAM, 0);
		if (sock == -1)
		{
			g_critical ("failed to create a socket: %s", strerror (errno));
			ret = ASPAMD_ERR_NET;
			goto at_exit;
		}
		g_debug ("socket %i is opened", sock);
		memset(&sock_addr_un, 0, sizeof(sock_addr_un));
		sock_addr_un.sun_family = AF_UNIX;
		strcpy(sock_addr_un.sun_path, ip_path);

		if (connect (sock, (struct sockaddr *)&sock_addr_un,
			     sizeof (sock_addr_un)) == -1)
		{
			g_critical ("failed to connect the socket %i: %s",
				    sock, strerror (errno));
			ret = ASPAMD_ERR_NET;
			goto at_exit;
		}
		g_debug ("socket %i is connected to %s", sock, ip_path);
	}
	else
	{
		sock = socket (AF_INET, SOCK_STREAM, 0);
		if (sock == -1)
		{
			g_critical ("failed to create a socket: %s", strerror (errno));
			ret = ASPAMD_ERR_NET;
			goto at_exit;
		}
		g_debug ("socket %i is opened", sock);
		memset(&sock_addr_in, 0, sizeof(sock_addr_in));
		sock_addr_in.sin_port = htons(port);
		sock_addr_in.sin_family = AF_INET;
		if(inet_aton (ip_path, &sock_addr_in.sin_addr) < 0)
		{
			g_critical ("failed to form socket %i addr from string `%s'",
				    sock, ip_path);
			ret = ASPAMD_ERR_NET;
			goto at_exit;
		}

		if (connect (sock, (struct sockaddr *)&sock_addr_in,
			     sizeof (sock_addr_in)) == -1)
		{
			g_critical ("failed to connect the socket %i: %s",
				    sock, strerror (errno));
			ret = ASPAMD_ERR_NET;
			goto at_exit;
		}
		g_debug ("socket %i is connected to %s:%i", sock, ip_path, port);
	}

	cur_options = fcntl (sock, F_GETFL);
	if (cur_options < 0)
	{
		g_critical ("get socket %i options failed", sock);
		ret = ASPAMD_ERR_NET;
		goto at_exit;
	}
	cur_options |= O_NONBLOCK;
	if (fcntl(sock, F_SETFL, cur_options) < 0)
	{
		g_critical ("set socket %i options failed", sock);
		return ASPAMD_ERR_NET;
		goto at_exit;
	}
	
at_exit:
	if (ret == ASPAMD_ERR_OK)
		*new_sock = sock;
	else
	{
		if (sock > 0)
			close (sock);
		*new_sock = -1;
	}
	return ret;
}

gint write_request (gint sock, sample_message_t *sample)
{
	gint ret = ASPAMD_ERR_OK, bytes; 

	bytes = write (sock, sample->body, strlen (sample->body));
	if (bytes == -1)
	{
		g_critical ("write failed: %s", strerror (errno));
		ret = ASPAMD_ERR_IO;
		goto at_exit;
	}
	g_debug ("%i bytes written", bytes);

at_exit:
	return ret;
}

gint read_reply (int sock)
{
	gint ret = ASPAMD_ERR_OK,
		completed = 0,
		io_ret,
		offset = 0;
	struct pollfd poll_fds;

	buffer_filling = 0;

	poll_fds.fd = sock;
	poll_fds.events = POLLIN | POLLPRI | POLLERR;
	while (!completed && ret == ASPAMD_ERR_OK)
	{
		io_ret = poll (&poll_fds, 1, TEST_IO_READ_TIMEOUT * 1000);
		if (io_ret == -1)
		{
			g_critical ("poll failed: %s", strerror (errno));
			ret = ASPAMD_ERR_IO;
			goto at_exit;
		}
		else if (io_ret == 0)
		{
			g_critical ("read timeout");
			ret = ASPAMD_ERR_IO;
			goto at_exit;
		}

		if (TEST_BUFFER_SIZE - buffer_filling <= 0)
		{
			g_critical ("no space in the buffer");
			ret = ASPAMD_ERR_IO;
			goto at_exit;
		}

		io_ret = read (sock, buffer + buffer_filling,
			      TEST_BUFFER_SIZE - buffer_filling);
		if (io_ret == -1)
		{
			g_critical ("read failed: %s", strerror (errno));
			ret = ASPAMD_ERR_IO;
			goto at_exit;
		}
		else if (io_ret == 0)
		{
			g_critical ("remote side closed the connection");
			ret = ASPAMD_ERR_NET;
			goto at_exit;
		}
		g_debug ("%i bytes read", io_ret);
		buffer_filling += io_ret;
		ret = assassin_parser_scan(parser, buffer, &offset, buffer_filling,
					   &completed, 0);
	}
	g_debug ("parser: completed - %i, ret - %i", completed, ret);
at_exit:
	return ret;
}

gint check_reply (sample_message_t *sample)
{
	gint ret = ASPAMD_ERR_OK;
	assassin_message_t *message = NULL;
	GVariant *header;
	gboolean spam;
	gint numerator, denominator;
	gchar *body;
	gint body_size = 0;

	message = assassin_parser_get (parser);

	if (!sample)
	{

		if (message->error == assassin_ex_ioerr)
		{
			assassin_buffer_get_data (message->content, (gpointer *)&body,
						  &body_size);
			if(g_ascii_strncasecmp (body, "maximum number of connections "
						"is achieved\r\n",
						body_size) == 0)
			{
				g_message ("server reached maximum connections number");
				stats.refused ++;
				goto at_exit;
			}
			if(g_ascii_strncasecmp (body, "message read timeout\r\n",
						body_size) == 0)
			{
				g_message ("read timeout");
				stats.err_msgs ++;
				goto at_exit;
			}
		}
		ret = ASPAMD_ERR_ERR;
		goto at_exit;
	}

	switch (sample->type)
	{
	case message_ping:
		stats.pings ++;
		break;
	case message_spam:
	case message_not_spam:
	{
		stats.msgs ++;
		if (message->error != assassin_ex_ok)
		{
			g_critical ("unexpected error code - %i", message->error);
			ret = ASPAMD_ERR_ERR;
			goto at_exit;
		}	
		break;
	}
	case message_error:
	{
		stats.err_msgs ++;
		if (message->error == assassin_ex_ok)
		{
			g_critical ("unexpected error code - %i", message->error);
			ret = ASPAMD_ERR_ERR;
			goto at_exit;
		}
		break;
	}
	}

	switch (sample->type)
	{
	case message_spam:
	case message_not_spam:
	{
		header = assassin_msg_find_header (message, assassin_hdr_spam);
		if (!header)
		{
			g_critical ("spam header is not found");
			ret = ASPAMD_ERR_ERR;
			goto at_exit;
		}
		g_variant_get (header, "(bii)", &spam, &numerator, &denominator);
		if ((sample->type == message_spam && !spam) ||
		    (sample->type == message_not_spam && spam))
		{
			g_critical ("wrong spam status");
			ret = ASPAMD_ERR_ERR;
			goto at_exit;
		}
		if (sample->rating != numerator)
		{
			g_critical ("wrong spam rating");
			ret = ASPAMD_ERR_ERR;
			goto at_exit;
		}
		break;
	}
	}

at_exit:
	if (ret == ASPAMD_ERR_OK)
		g_debug ("PASSED");
	if (message)
		assassin_msg_free (message);
	return ret;
}

static void dump_buffer (const gchar *buffer, gint size)
{
	gchar *sub_string = NULL, *clean_string = NULL;

	if (size > 60)
		size = 60;
	sub_string = g_strndup (buffer, size);
	g_assert (sub_string);
	clean_string = g_strescape (sub_string, NULL);
	g_assert (clean_string);
	g_critical ("buffer dump: %s", clean_string);
	g_free (sub_string);
	g_free (clean_string);
}

gint sock_loop ()
{
	gint ret = ASPAMD_ERR_OK;
	gint sock = -1, messages_num, buggy_msg_num, refused = 0;
	sample_message_t *sample = NULL;
	gint dice;

	for (messages_num = 1; messages[messages_num - 1].body; messages_num++);
	for (buggy_msg_num = 1; buggy_messages[buggy_msg_num - 1].body; buggy_msg_num++);

	g_debug ("messages - %i, buggy messages - %i", messages_num, buggy_msg_num);

	running = 1;
	while (running)
	{
		buffer_filling = 0;
		if (server_ip)
			ret = sock_open_connect (&sock, server_ip, server_port);
		else
			ret = sock_open_connect (&sock, sock_path, 0);
		if (ret != ASPAMD_ERR_OK)
		{
			refused++;
			if (refused < TEST_MAX_REFUSED)
			{
				random_delay (TEST_CLNT_RATE_FAST);
				continue;
			}
			else
			{
				g_critical ("maximum number of connect attemps is reached");
				stats.refused = refused;
				break;
			}
			
		}
		refused = 0;
		
		if (client_manner == TEST_CLNT_CLEVER)
			sample = &messages[random () % (messages_num - 1)];
		else if (client_manner == TEST_CLNT_BUGGY)
		{
			dice = random () % 100;
			if (dice >= 0 && dice < 33)
				sample = &messages[random () % (messages_num - 1)];
			else if (dice >= 33 && dice < 66)
			{
				sample = &buggy_messages[random () % (buggy_msg_num - 1)];
				g_message ("behaving buggy: buggy message");
			}
			else
			{
				sample = NULL;
				g_message ("behaving buggy: no message");
			}
		}

		if (sample)
		{
			g_debug ("sample type - %i, rating - %i, size - %i",
				 sample->type, sample->rating, (int) strlen (sample->body));

			ret = write_request (sock, sample);
			ASPAMD_ERR_CHECK (ret);

			if (client_manner == TEST_CLNT_BUGGY)
			{
				if (random () % 100 > 50)
				{
					g_message ("behaving buggy: reply is skipped");
					goto at_exit;
				}
			}
		}

		ret = read_reply (sock);
		ASPAMD_ERR_CHECK (ret);

		ret = check_reply (sample);
		ASPAMD_ERR_CHECK (ret);
at_exit:
		if (sock > 0 )
		{
			close (sock);
			sock = -1;
		}
		assassin_parser_reset (parser);
		if (ret != ASPAMD_ERR_OK && client_manner == TEST_CLNT_CLEVER)
		{
			dump_buffer (buffer, MIN (buffer_filling, (TEST_BUFFER_SIZE - 1)));
			running = 0;
		}
		else
			random_delay (client_rate);
	}
	g_debug ("connections refused - %i", stats.refused);
	g_debug ("messages sent - %i", stats.msgs);
	g_debug ("error messages sent - %i", stats.err_msgs);
	g_debug ("pings sent - %i", stats.pings);

	return ret;
}

void sig_handler (int sig_no)
{
	g_message ("stopping");
	running = 0;
}

gint initialize ()
{
	gint ret = ASPAMD_ERR_OK;
	struct sigaction action;

	srandom (time (NULL));
	aspamd_logger_early_configure (&logger);
	ret = assassin_parser_allocate (&parser, assassin_msg_reply, 1);
	ASPAMD_ERR_CHECK (ret);
	action.sa_handler = &sig_handler;
	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;
	if (sigaction (SIGINT, &action, NULL) == -1)
	{
		ret = ASPAMD_ERR_ERR;
		goto at_exit;
	}
	if (sigaction (SIGTERM, &action, NULL) == -1)
	{
		ret = ASPAMD_ERR_ERR;
		goto at_exit;
	}
	if (sigaction (SIGQUIT, &action, NULL) == -1)
	{
		ret = ASPAMD_ERR_ERR;
		goto at_exit;
	}
	memset (&stats, 0, sizeof (stats));
at_exit:
	return ret;
}

void random_delay (gint client_rate)
{
	gint seconds;

	switch (client_rate)
	{
	case TEST_CLNT_RATE_SLOW:
		seconds = 45 + random () % 16;
		break;
	case TEST_CLNT_RATE_MEDIUM:
		seconds = 15 + random () % 10;
		break;
	case TEST_CLNT_RATE_FAST:
		seconds = random () % 10;
		break;
	case TEST_CLNT_RATE_NO_DELAY:
		return;
	}
	g_message ("%i seconds delay", seconds);
	sleep (seconds);
}

void deinitialize ()
{
	if (server_ip != default_server_ip)
		g_free (server_ip);
	if (parser)
		assassin_parser_free (parser);
}

int main (int argc, char *argv[])
{
	gint ret = ASPAMD_ERR_OK;

	ret = initialize ();
	ASPAMD_ERR_CHECK (ret);
	ret = parse_com_line (argc, argv);
	ASPAMD_ERR_CHECK (ret);
	sock_loop ();
at_exit:
	deinitialize ();
	return ret;
}

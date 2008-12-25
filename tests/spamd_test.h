/* 
 * aspamd - advanced spam daemon 
 *
 */

#ifndef _SPAMD_TEST_
#define _SPAMD_TEST_

#define TEST_DEFAULT_PORT		(783)
#define TEST_DEFAULT_IP			"127.0.0.1"
#define TEST_DEFAULT_SOCK_PATH		"aspamd.sock"
#define TEST_MAX_REFUSED		(10)
#define TEST_BUFFER_SIZE		(ASSASSIN_MAX_HEAD_SIZE*2)
#define TEST_IO_READ_TIMEOUT		(30)


enum test_client_rate
{
	TEST_CLNT_RATE_NO_DELAY = 0,
	TEST_CLNT_RATE_FAST,
	TEST_CLNT_RATE_MEDIUM,
	TEST_CLNT_RATE_SLOW
};

enum test_client_manner
{
	TEST_CLNT_CLEVER = 0,
	TEST_CLNT_BUGGY
};

#endif

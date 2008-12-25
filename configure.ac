AC_PREREQ([2.59])

AC_INIT([advanced spam filtering daemon], [0.1.0], [johnsmith@yahoo.com], [aspamd], [])
AM_INIT_AUTOMAKE([subdir-objects])

AC_PROG_CC
AC_PROG_CC_STDC
AM_PROG_CC_C_O

PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.24])
AC_SUBST([GLIB_CFLAGS])
AC_SUBST([GLIB_LIBS])

PKG_CHECK_MODULES([KAS], [kas >= 4.1])
AC_SUBST([KAS_CFLAGS])
AC_SUBST([KAS_LIBS])

PKG_CHECK_MODULES([GTHREAD], [gthread-2.0 >= 2.24])
AC_SUBST([GTHREAD_CFLAGS])
AC_SUBST([GTHREAD_LIBS])

AC_MSG_CHECKING([debug mode enabled])
AC_ARG_ENABLE(debug_mode, AC_HELP_STRING([--enable-debug-mode],
	[Enable debugging mode]))
AS_IF([test "x$enable_debug_mode" = xyes],
	[AC_DEFINE(ASPAMD_NET_MAX_CON, 4, [Maximal number of connection to be served])
	AC_DEFINE(ASPAMD_DEBUG_MODE, 1, [Debug mode enabled])
	CFLAGS="-g3 -O0 -Wall"
	AC_SUBST([CFLAGS])
	AC_MSG_RESULT([yes ($CFLAGS)])],
	[AC_DEFINE(ASPAMD_NET_MAX_CON, 1024,
	[Maximal number of connection to be served])
	AC_MSG_RESULT([no])])

AC_DEFINE(ASPAMD_DEFAULT_LOG_PATH, "/var/log/aspamd.log",
				   [Default path to log file])
AC_DEFINE(ASPAMD_DEFAULT_LOG_TYPE, aspamd_log_syslog, [Default logger type])
AC_DEFINE(ASPAMD_DEFAULT_LOG_LEVEL, (G_LOG_LEVEL_MESSAGE | \
				    G_LOG_LEVEL_WARNING | \
				    G_LOG_LEVEL_CRITICAL | \
				    G_LOG_LEVEL_ERROR), [Default log level])
AC_DEFINE(ASPAMD_MAX_LINE_LEN, 512, [Maximal log line length])

AC_DEFINE(ASPAMD_DEFAULT_KAS_WORK_PATH, "/var/lib/aspamd/temp",
					[KAS default work directory])
AC_DEFINE(ASPAMD_DEFAULT_KAS_LIC_PATH, "/var/lib/aspamd/license",
				       [KAS default license path])
AC_DEFINE(ASPAMD_DEFAULT_KAS_UPDATE_PATH, "/var/lib/aspamd/bases",
					  [KAS default DB path])
AC_DEFINE(ASPAMD_DEFAULT_KAS_QUEUE_SIZE, 256, [KAS engine queue size to keep requests])
AC_DEFINE(ASPAMD_DEFAULT_KAS_THREADS_COUNT, 16, [KAS engine threads number])

AC_DEFINE(ASPAMD_REACTOR_TIMEOUT, 1000, [Network polling timeout in milliseconds])

AC_DEFINE(ASSASSIN_MAX_HEAD_SIZE, 1024, [Maximal Assassin header size])

AC_DEFINE(ASPAMD_DEFAULT_SERVER_IP, "127.0.0.1", [Default server IPv4 addres])
AC_DEFINE(ASPAMD_DEFAULT_SERVER_PORT, 783, [Default server TCP port])
AC_DEFINE(ASPAMD_DEFAULT_SOCKET_PATH, "/var/run/aspamd/socket",
				      [Default server UNIX socket path])
AC_DEFINE(ASPAMD_DEFAULT_TIMEOUT, 20, [Session timeout])
AC_DEFINE(ASPAMD_STAT_ENTRIES, 1024, [Maximal size of list to keep statistic])


AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

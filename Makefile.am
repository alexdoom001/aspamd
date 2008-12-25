bin_PROGRAMS = aspamd parser_test

aspamd_SOURCES = src/aspamd.c src/logging.c src/server.c src/session.c\
	src/parser.c src/assassin.c src/kas.c
aspamd_CFLAGS = $(KAS_CFLAGS) $(GLIB_CFLAGS) -Isrc -DG_LOG_DOMAIN=\"aspamd\"
aspamd_LDFLAGS = $(KAS_LIBS) $(GLIB_LIBS)

parser_test_SOURCES = src/parser.c src/assassin.c tests/parser_test.c src/logging.c
parser_test_CFLAGS = $(GLIB_CFLAGS) -Isrc -DG_LOG_DOMAIN=\"parser_test\"
parser_test_LDFLAGS = $(GLIB_LIBS)

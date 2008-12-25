bin_PROGRAMS = aspamd parser_test spamd_test

aspamd_SOURCES = src/aspamd.c src/logging.c src/server.c src/session.c\
	src/parser.c src/assassin.c src/pairs.c src/kas.c src/reactor.c
aspamd_CFLAGS = $(KAS_CFLAGS) $(GLIB_CFLAGS) $(GTHREAD_FLAGS) -Isrc -DG_LOG_DOMAIN=\"aspamd\"
aspamd_LDFLAGS = $(KAS_LIBS) $(GLIB_LIBS) $(GTHREAD_LIBS)

parser_test_SOURCES = src/parser.c src/assassin.c src/pairs.c src/logging.c \
	tests/parser_test.c
parser_test_CFLAGS = $(GLIB_CFLAGS) -Isrc -Itests -DG_LOG_DOMAIN=\"parser_test\"
parser_test_LDFLAGS = $(GLIB_LIBS)

spamd_test_SOURCES = src/parser.c src/assassin.c src/pairs.c src/logging.c \
	tests/spam_samples.c tests/spamd_test.c
spamd_test_CFLAGS = $(GLIB_CFLAGS) -Isrc -Itests -DG_LOG_DOMAIN=\"spamd_test\"
spamd_test_LDFLAGS = $(GLIB_LIBS)

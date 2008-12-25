#!/bin/sh

# setting environment to make GLib debugging handy

# This will cause all slices allocated through g_slice_alloc() and
# released by g_slice_free1() to be actually allocated via direct
# calls to g_malloc() and g_free(). This is most useful for memory
# checkers and similar programs that use Bohem GC alike algorithms to
# produce more accurate results
export G_SLICE=always-malloc


# Newly allocated memory that isn't directly initialized, as well as
# memory being freed will be reset to 0. The point here is to allow
# memory checkers and similar programs that use bohem GC alike
# algorithms to produce more accurate results. This option is special
# in that it doesn't require GLib to be configured with debugging
# support.
export G_DEBUG=gc-friendly

valgrind --leak-check=full --log-file=valgrind.log $@

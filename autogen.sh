#!/bin/sh

autoreconf -fiv --include tests/cbtest
rm -Rf autom4te.cache

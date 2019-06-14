#!/bin/sh

autoreconf -fiv --include tests/cstor
rm -Rf autom4te.cache

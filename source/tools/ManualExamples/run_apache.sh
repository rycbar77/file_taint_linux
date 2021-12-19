#!/bin/sh
../../../pin -follow-execv -t obj-intel64/file_taint.so -- /usr/sbin/apache2ctl -D FOREGROUND
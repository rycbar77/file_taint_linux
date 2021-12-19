#!/bin/sh
kill -9 `ps -aux|grep apache |awk '{print $2}'`
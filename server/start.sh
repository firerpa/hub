#!/bin/sh
exec python3 -u -m server -ckey=${TOP_CLIENT_KEY} -endpoint=${TOP_ENDPOINT} -secret=${TOP_SECRET} $@
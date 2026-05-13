#!/bin/sh
# Run php-fpm and nginx in parallel. Whichever exits first takes the
# container down so docker (or k8s, or systemd) can restart cleanly —
# without this, a php-fpm crash leaves nginx serving 502s.
set -e

php-fpm -F &
php_pid=$!

nginx -g 'daemon off;' &
nginx_pid=$!

trap 'kill -TERM "$php_pid" "$nginx_pid" 2>/dev/null || true' TERM INT

wait -n "$php_pid" "$nginx_pid"
exit_code=$?

kill -TERM "$php_pid" "$nginx_pid" 2>/dev/null || true
wait "$php_pid" "$nginx_pid" 2>/dev/null || true
exit "$exit_code"

#!/bin/sh

DAEMON=/usr/bin/aesdsocket
PIDFILE=/var/run/aesdsocket.pid
NAME=aesdsocket

start() {
    echo "Starting $NAME..."
    start-stop-daemon -S -n $NAME -p $PIDFILE -m -b -x $DAEMON -- -d
}

stop() {
    echo "Stopping $NAME..."
    start-stop-daemon -K -n $NAME -p $PIDFILE --retry=TERM/10/KILL/5
    rm -f $PIDFILE
}

case "$1" in
    start) start ;;
    stop) stop ;;
    restart) stop; start ;;
    *) echo "Usage: $0 {start|stop|restart}"; exit 1 ;;
esac

exit 0
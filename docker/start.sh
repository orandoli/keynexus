#!/bin/sh

if [ -n "${UMASK}" ]; then
    umask "${UMASK}"
fi

if [ -r /etc/pwdsv.sh ]; then
    . /etc/pwdsv.sh
elif [ -r /etc/bitwarden_rs.sh ]; then
    echo "### You are using the old /etc/bitwarden_rs.sh script, please migrate to /etc/pwdsv.sh ###"
    . /etc/bitwarden_rs.sh
fi

if [ -d /etc/pwdsv.d ]; then
    for f in /etc/pwdsv.d/*.sh; do
        if [ -r "${f}" ]; then
            . "${f}"
        fi
    done
elif [ -d /etc/bitwarden_rs.d ]; then
    echo "### You are using the old /etc/bitwarden_rs.d script directory, please migrate to /etc/pwdsv.d ###"
    for f in /etc/bitwarden_rs.d/*.sh; do
        if [ -r "${f}" ]; then
            . "${f}"
        fi
    done
fi

exec /pwdsv "${@}"

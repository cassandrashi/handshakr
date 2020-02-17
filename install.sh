#!/usr/bin/env bash

# Copyright ©2020 handshake.moe
# All rights reserved

echo '-- Checking for required tools...'

HAS_GIT=$(which git)
if [ -z "$HAS_GIT" ]; then
  echo 'Your machine does not have git installed. Please install it and try again.'
  exit 0
fi

HAS_NODE=$(which node)
if [ -z "$HAS_NODE" ]; then
  echo 'Your machine does not have node installed. Please install it and try again.'
  exit 0
fi

echo '-- Downloading...'
WORKDIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'mytmpdir')
curl -o "$WORKDIR/handshakr.zip" -L --progress-bar "https://github.com/handshakemoe/handshakr/archive/master.zip"
unzip -q -d $WORKDIR "$WORKDIR/handshakr.zip"
cd "$WORKDIR/handshakr-master"

echo '-- Installing dependencies...'
npm install -s --no-audit

echo '-- Starting helper...'
exec < /dev/tty node "$WORKDIR/handshakr-master/main.js"

# Clean up
rm -r $WORKDIR
exit 0

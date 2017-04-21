#!/bin/bash

MAKE_RESOLV_CONF_FUNCTION=make_resolv_conf

USAGE="$0 <path to virtual environment to place executable>
The script takes existing dhclient-script and makes $MAKE_RESOLV_CONF_FUNCTION function a noop function.
"

if [ $# -lt 1 ]; then
    echo "Path to virtual environment directory is a required parameter."
    echo $USAGE
    exit 2
fi

VENV_DIR=$1
DHCLIENT_SCRIPT_NAME=dhclient-script
DHCLIENT_PATH=$(which $DHCLIENT_SCRIPT_NAME)
FULLSTACK_DHCLIENT_SCRIPT=$VENV_DIR/bin/fullstack-dhclient-script

if [ -n "$DHCLIENT_PATH" ]; then
    # Return from make_resolv_conf function immediately. This will cause
    # that /etc/resolv.conf will not be updated by fake fullstack machines.
    sed "/^$MAKE_RESOLV_CONF_FUNCTION()/a\    return" $DHCLIENT_PATH > $FULLSTACK_DHCLIENT_SCRIPT
    chmod +x $FULLSTACK_DHCLIENT_SCRIPT
else
    echo "$DHCLIENT_SCRIPT_NAME not found."
    exit 1
fi

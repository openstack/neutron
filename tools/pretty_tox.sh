#! /bin/sh

TESTRARGS=$1

exec 3>&1
status=$(exec 4>&1 >&3; ( python -m neutron.openstack.common.lockutils python setup.py testr --slowest --testr-args="--subunit $TESTRARGS"; echo $? >&4 ) | subunit-trace -f) && exit $status

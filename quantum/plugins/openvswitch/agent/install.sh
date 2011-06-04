#!/bin/bash

CONF_FILE=/etc/xapi.d/plugins/ovs_quantum_plugin.ini

if [ ! -d /etc/xapi.d/plugins ]; then
	echo "Am I on a xenserver? I can't find the plugins directory!"
	exit 1
fi

# Make sure we have mysql-python
rpm -qa | grep MYyQL-python >/dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "MySQL-python not found; installing."
	yum -y install MySQL-python
	if [ $? -ne 0 ]; then
		echo "Failed to install MYSQL-python; agent will not work."
		exit 1
	fi
fi

cp ovs_quantum_agent.py /etc/xapi.d/plugins
cp ovs_quantum_plugin.ini /etc/xapi.d/plugins
cp set_external_ids.sh /etc/xapi.d/plugins

xe network-list name-label="integration-bridge" | grep xapi >/dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "No integration bridge found.  Creating."
	xe network-create name-label="integration-bridge"
fi

BR=$(xe network-list name-label="integration-bridge" | grep "bridge.*:" | awk '{print $4}')
CONF_BR=$(grep integration-bridge ${CONF_FILE} | cut -d= -f2)
if [ "X$BR" != "X$CONF_BR" ]; then
	echo "Integration bridge doesn't match configuration file; fixing."
	sed -i -e "s/^integration-bridge =.*$/integration-bridge = ${BR}/g" $CONF_FILE
fi

echo "Make sure to edit: $CONF_FILE"

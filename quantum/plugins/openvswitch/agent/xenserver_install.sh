#!/bin/bash

CONF_FILE=/etc/xapi.d/plugins/ovs_quantum_plugin.ini
VERSION=$(python -c "import sys ; sys.path.append('../../../../quantum/') ; import version ; print version.canonical_version_string()")

if [ ! -d /etc/xapi.d/plugins ]; then
    echo "Am I on a xenserver? I can't find the plugins directory!"
    exit 1
fi

rpm -Uvh http://dl.fedoraproject.org/pub/epel/5/i386/epel-release-5-4.noarch.rpm

if [ "$1" == "with_python_2.6" ] ; then
    yum --enablerepo=base -y install mx
    yum --enablerepo=epel -y install python26 python26-sqlalchemy python26-mysqldb
else
    yum --enablerepo=epel -y install python-sqlalchemy
    yum --enablerepo=base -y install MySQL-python
fi

sed -i 's/enabled=1/enabled=0/' /etc/yum.repos.d/epel.repo

rpm -Uvh $PWD/build/rpm/RPMS/noarch/ovs-quantum-agent-$VERSION-1.noarch.rpm

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

echo "Using integration bridge: $BR (make sure this is set in the nova configuration)"

echo "Make sure to edit: $CONF_FILE"

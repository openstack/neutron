#!/bin/bash

set -ex

venv=${1:-"dsvm-functional"}

CONTRIB_DIR="$BASE/new/neutron/neutron/tests/contrib"

$BASE/new/devstack-gate/devstack-vm-gate.sh

if [ "$venv" == "dsvm-functional" ]
then
    # Add a rootwrap filter to support test-only
    # configuration (e.g. a KillFilter for processes that
    # use the python installed in a tox env).
    FUNC_FILTER=$CONTRIB_DIR/filters.template
    sed -e "s+\$BASE_PATH+$BASE/new/neutron/.tox/dsvm-functional+" \
        $FUNC_FILTER | sudo tee /etc/neutron/rootwrap.d/functional.filters > /dev/null

    # Use devstack functions to install mysql and psql servers
    TOP_DIR=$BASE/new/devstack
    source $TOP_DIR/functions
    source $TOP_DIR/lib/config
    source $TOP_DIR/stackrc
    source $TOP_DIR/lib/database
    source $TOP_DIR/localrc

    disable_service postgresql
    enable_service mysql
    initialize_database_backends
    install_database

    disable_service mysql
    enable_service postgresql
    initialize_database_backends
    install_database

    # Set up the 'openstack_citest' user and database in each backend
    tmp_dir=`mktemp -d`

    cat << EOF > $tmp_dir/mysql.sql
CREATE DATABASE openstack_citest;
CREATE USER 'openstack_citest'@'localhost' IDENTIFIED BY 'openstack_citest';
CREATE USER 'openstack_citest' IDENTIFIED BY 'openstack_citest';
GRANT ALL PRIVILEGES ON *.* TO 'openstack_citest'@'localhost';
GRANT ALL PRIVILEGES ON *.* TO 'openstack_citest';
FLUSH PRIVILEGES;
EOF
    /usr/bin/mysql -u root < $tmp_dir/mysql.sql

    cat << EOF > $tmp_dir/postgresql.sql
CREATE USER openstack_citest WITH CREATEDB LOGIN PASSWORD 'openstack_citest';
CREATE DATABASE openstack_citest WITH OWNER openstack_citest;
EOF
    # User/group postgres needs to be given access to tmp_dir
    setfacl -m g:postgres:rwx $tmp_dir
    sudo -u postgres /usr/bin/psql --file=$tmp_dir/postgresql.sql
fi

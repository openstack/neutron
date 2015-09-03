#!/usr/bin/env bash

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


set -e


# Control variable used to determine whether to execute this script
# directly or allow the gate_hook to import.
IS_GATE=${IS_GATE:-False}


if [[ "$IS_GATE" != "True" ]] && [[ "$#" -lt 1 ]]; then
    >&2 echo "Usage: $0 /path/to/devstack [-i]
Configure a host to run Neutron's functional test suite.

-i   Install Neutron's package dependencies.  By default, it is assumed
     that devstack has already been used to deploy neutron to the
     target host and that package dependencies need not be installed.

Warning: This script relies on devstack to perform extensive
modification to the underlying host.  It is recommended that it be
invoked only on a throw-away VM."
    exit 1
fi


# Skip the first argument
OPTIND=2
while getopts ":i" opt; do
    case $opt in
        i)
            INSTALL_BASE_DEPENDENCIES=True
            ;;
    esac

done

# Default to environment variables to permit the gate_hook to override
# when sourcing.
VENV=${VENV:-dsvm-functional}
DEVSTACK_PATH=${DEVSTACK_PATH:-$1}
PROJECT_NAME=${PROJECT_NAME:-neutron}
REPO_BASE=${GATE_DEST:-$(cd $(dirname "$0")/../.. && pwd)}
# The gate should automatically install dependencies.
INSTALL_BASE_DEPENDENCIES=${INSTALL_BASE_DEPENDENCIES:-$IS_GATE}


if [ ! -f "$DEVSTACK_PATH/stack.sh" ]; then
  >&2 echo "Unable to find devstack at '$DEVSTACK_PATH'.  Please verify that the specified path points to a valid devstack repo."
  exit 1
fi


set -x


function _init {
    # Subsequently-called devstack functions depend on the following variables.
    HOST_IP=127.0.0.1
    FILES=$DEVSTACK_PATH/files
    TOP_DIR=$DEVSTACK_PATH

    source $DEVSTACK_PATH/stackrc

    # Allow the gate to override values set by stackrc.
    DEST=${GATE_DEST:-$DEST}
    STACK_USER=${GATE_STACK_USER:-$STACK_USER}
}


function _install_base_deps {
    echo_summary "Installing base dependencies"

    INSTALL_TESTONLY_PACKAGES=True
    PACKAGES=$(get_packages general neutron,q-agt,q-l3)
    # Do not install 'python-' prefixed packages other than
    # python-dev*.  Neutron's functional testing relies on deployment
    # to a tox env so there is no point in installing python
    # dependencies system-wide.
    PACKAGES=$(echo $PACKAGES | perl -pe 's|python-(?!dev)[^ ]*||g')
    install_package $PACKAGES
}


function _install_rpc_backend {
    echo_summary "Installing rabbitmq"

    RABBIT_USERID=${RABBIT_USERID:-stackrabbit}
    RABBIT_HOST=${RABBIT_HOST:-$SERVICE_HOST}
    RABBIT_PASSWORD=${RABBIT_HOST:-secretrabbit}

    source $DEVSTACK_PATH/lib/rpc_backend

    enable_service rabbit
    install_rpc_backend
    restart_rpc_backend
}


function _install_databases {
    echo_summary "Installing databases"

    # Avoid attempting to configure the db if it appears to already
    # have run.  The setup as currently defined is not idempotent.
    if mysql openstack_citest > /dev/null 2>&1 < /dev/null; then
        echo_summary "DB config appears to be complete, skipping."
        return 0
    fi

    MYSQL_PASSWORD=${MYSQL_PASSWORD:-secretmysql}
    DATABASE_PASSWORD=${DATABASE_PASSWORD:-secretdatabase}

    source $DEVSTACK_PATH/lib/database

    disable_service postgresql
    enable_service mysql
    initialize_database_backends
    install_database
    configure_database_mysql

    disable_service mysql
    enable_service postgresql
    initialize_database_backends
    install_database
    configure_database_postgresql

    # Set up the 'openstack_citest' user and database in each backend
    tmp_dir=$(mktemp -d)
    trap "rm -rf $tmp_dir" EXIT

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
}


function _install_agent_deps {
    echo_summary "Installing agent dependencies"

    source $DEVSTACK_PATH/lib/neutron-legacy

    ENABLED_SERVICES=q-agt,q-dhcp,q-l3
    install_neutron_agent_packages
}


# Set up the rootwrap sudoers for neutron to target the rootwrap
# configuration deployed in the venv.
function _install_rootwrap_sudoers {
    echo_summary "Installing rootwrap sudoers file"

    PROJECT_VENV=$REPO_BASE/$PROJECT_NAME/.tox/$VENV
    ROOTWRAP_SUDOER_CMD="$PROJECT_VENV/bin/neutron-rootwrap $PROJECT_VENV/etc/neutron/rootwrap.conf *"
    ROOTWRAP_DAEMON_SUDOER_CMD="$PROJECT_VENV/bin/neutron-rootwrap-daemon $PROJECT_VENV/etc/neutron/rootwrap.conf"
    TEMPFILE=$(mktemp)
    cat << EOF > $TEMPFILE
# A bug in oslo.rootwrap [1] prevents commands executed with 'ip netns
# exec' from being automatically qualified with a prefix from
# rootwrap's configured exec_dirs.  To work around this problem, add
# the venv bin path to a user-specific secure_path.
#
# While it might seem preferable to set a command-specific
# secure_path, this would only ensure the correct path for 'ip netns
# exec' and the command targeted for execution in the namespace would
# not inherit the path.
#
# 1: https://bugs.launchpad.net/oslo.rootwrap/+bug/1417331
#
Defaults:$STACK_USER  secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PROJECT_VENV/bin"
$STACK_USER ALL=(root) NOPASSWD: $ROOTWRAP_SUDOER_CMD
$STACK_USER ALL=(root) NOPASSWD: $ROOTWRAP_DAEMON_SUDOER_CMD
EOF
    chmod 0440 $TEMPFILE
    sudo chown root:root $TEMPFILE
    # Name the functional testing rootwrap to ensure that it will be
    # loaded after the devstack rootwrap (50_stack_sh if present) so
    # that the functional testing secure_path (a superset of what
    # devstack expects) will not be overwritten.
    sudo mv $TEMPFILE /etc/sudoers.d/60-neutron-func-test-rootwrap
}


function _install_post_devstack {
    echo_summary "Performing post-devstack installation"

    _install_databases
    _install_rootwrap_sudoers

    # Installing python-openvswitch from packages is a stop-gap while
    # python-openvswitch remains unavailable from pypi.  This also
    # requires that sitepackages=True be set in tox.ini to allow the
    # venv to use the installed package.  Once python-openvswitch
    # becomes available on pypi, this will no longer be required.
    #
    # NOTE: the package name 'python-openvswitch' is common across
    # supported distros.
    install_package python-openvswitch
}


function configure_host_for_func_testing {
    echo_summary "Configuring host for functional testing"

    if [[ "$INSTALL_BASE_DEPENDENCIES" == "True" ]]; then
        # Installing of the following can be achieved via devstack by
        # installing neutron, so their installation is conditional to
        # minimize the work to do on a devstack-configured host.
        _install_base_deps
        _install_agent_deps
        _install_rpc_backend
    fi
    _install_post_devstack
}


_init


if [[ "$IS_GATE" != "True" ]]; then
    configure_host_for_func_testing
fi

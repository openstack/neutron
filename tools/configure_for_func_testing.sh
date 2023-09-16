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
USE_CONSTRAINT_ENV=${USE_CONSTRAINT_ENV:-True}
MYSQL_USER=${MYSQL_USER:-root}
DATABASE_USER=${DATABASE_USER:-openstack_citest}
DATABASE_NAME=${DATABASE_NAME:-openstack_citest}
MEMORY_TRACKER=${MEMORY_TRACKER:-False}
MYSQL_REDUCE_MEMORY=${MYSQL_REDUCE_MEMORY:-True}


if [[ "$IS_GATE" != "True" ]] && [[ "$#" -lt 1 ]]; then
    >&2 echo "Usage: $0 /path/to/devstack [-i]
Configure a host to run Neutron's functional test suite.

-i  Install Neutron's package dependencies.  By default, it is assumed
    that devstack has already been used to deploy neutron to the
    target host and that package dependencies need not be installed.

Warning: This script relies on devstack to perform extensive
modification to the underlying host.  It is recommended that it be
invoked only on a throw-away VM.

NOTE: Default values in this file, such as passwords, have been taken
from the devstack samples/local.conf file, but can be over-ridden by
setting them in your environment if necessary."
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
NEUTRON_DIR=${NEUTRON_DIR:=$REPO_BASE/$PROJECT_NAME}
INSTALL_MYSQL_ONLY=${INSTALL_MYSQL_ONLY:-False}
# The gate should automatically install dependencies.
INSTALL_BASE_DEPENDENCIES=${INSTALL_BASE_DEPENDENCIES:-$IS_GATE}
INSTALL_OVN=${INSTALL_OVN:-True}
Q_BUILD_OVS_FROM_GIT=${Q_BUILD_OVS_FROM_GIT:-True}
OVN_BRANCH=${OVN_BRANCH:-v23.09.0}
# OVS_BRANCH needs to be updated along with OVN_BRANCH, ovs is
# being used as submodule in ovn repo, to get a working ovs
# version can use git submodule status command on ovn repo
OVS_BRANCH=${OVS_BRANCH:-v3.2.0-20-g1d78a3f31}


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

    if [ -f $DEVSTACK_PATH/local.conf ]; then
        source $DEVSTACK_PATH/local.conf 2> /dev/null || true
    fi

    source $DEVSTACK_PATH/stackrc

    # Allow the gate to override values set by stackrc.
    DEST=${GATE_DEST:-$DEST}
    STACK_USER=${GATE_STACK_USER:-$STACK_USER}

    GetDistro
    source $DEVSTACK_PATH/tools/fixup_stuff.sh
}

function _install_base_deps {
    echo_summary "Installing base dependencies"

    INSTALL_TESTONLY_PACKAGES=True
    if [[ "$Q_BUILD_OVS_FROM_GIT" == "True" ]]; then
        PACKAGES=$(get_packages general,neutron,q-agt,q-l3)
        # Do not install 'python-' prefixed packages other than
        # python-dev*.  Neutron's functional testing relies on deployment
        # to a tox env so there is no point in installing python
        # dependencies system-wide.
        PACKAGES=$(echo $PACKAGES | perl -pe 's|python-(?!dev)[^ ]*||g')
        install_package $PACKAGES

        source $DEVSTACK_PATH/lib/neutron_plugins/ovn_agent
        echo_summary "OVS_BRANCH: ${OVS_BRANCH}"
        compile_ovs False /usr/local /var
        if [[ "$INSTALL_OVN" == "True" ]]; then
            echo_summary "OVN_BRANCH: ${OVN_BRANCH}"
            compile_ovn /usr/local /var
        fi
    else
        PACKAGES=$(get_packages general,neutron,q-agt,q-l3,openvswitch)
        PACKAGES=$(echo $PACKAGES | perl -pe 's|python-(?!dev)[^ ]*||g')
        install_package $PACKAGES
    fi

    if is_ubuntu && [[ "$DISTRO" != "bionic" ]]; then
        install_package "ncat"
    fi
}


function _install_rpc_backend {
    echo_summary "Installing rabbitmq"

    RABBIT_USERID=${RABBIT_USERID:-stackrabbit}
    RABBIT_HOST=${RABBIT_HOST:-$SERVICE_HOST}
    RABBIT_PASSWORD=${RABBIT_PASSWORD:-stackqueue}

    source $DEVSTACK_PATH/lib/rpc_backend

    enable_service rabbit
    install_rpc_backend
    restart_rpc_backend
}


# _install_databases [install_pg]
function _install_databases {
    local install_pg=${1:-True}

    echo_summary "Installing databases"

    # Avoid attempting to configure the db if it appears to already
    # have run.  The setup as currently defined is not idempotent.
    if mysql ${DATABASE_NAME} > /dev/null 2>&1 < /dev/null; then
        echo_summary "DB config appears to be complete, skipping."
        return 0
    fi

    MYSQL_PASSWORD=${MYSQL_PASSWORD:-openstack_citest}
    DATABASE_PASSWORD=${DATABASE_PASSWORD:-openstack_citest}

    source $DEVSTACK_PATH/lib/database

    enable_service mysql
    initialize_database_backends
    install_database
    configure_database_mysql

    if [[ "$install_pg" == "True" ]]; then
        enable_service postgresql
        initialize_database_backends
        install_database
        configure_database_postgresql
    fi

    # Set up the '${DATABASE_USER}' user and '${DATABASE_NAME}' database in each backend
    tmp_dir=$(mktemp -d)
    trap "rm -rf $tmp_dir" EXIT

    cat << EOF > $tmp_dir/mysql.sql
CREATE DATABASE ${DATABASE_NAME};
CREATE USER '${DATABASE_USER}'@'localhost' IDENTIFIED BY '${MYSQL_PASSWORD}';
GRANT ALL PRIVILEGES ON *.* TO '${DATABASE_USER}'@'localhost';
FLUSH PRIVILEGES;
EOF
    /usr/bin/mysql -u $MYSQL_USER -p"$MYSQL_PASSWORD" < $tmp_dir/mysql.sql

    if [[ "$install_pg" == "True" ]]; then
        cat << EOF > $tmp_dir/postgresql.sql
CREATE USER ${DATABASE_USER} WITH CREATEDB LOGIN PASSWORD '${DATABASE_PASSWORD}';
CREATE DATABASE ${DATABASE_NAME} WITH OWNER ${DATABASE_USER};
EOF

        # User/group postgres needs to be given access to tmp_dir
        setfacl -m g:postgres:rwx $tmp_dir
        sudo -u root sudo -u postgres /usr/bin/psql --file=$tmp_dir/postgresql.sql
    fi
}


function _install_agent_deps {
    echo_summary "Installing agent dependencies"

    ENABLED_SERVICES=q-agt,q-dhcp,q-l3

    source $DEVSTACK_PATH/lib/neutron

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

    SECURE_PATH="$PROJECT_VENV/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    if [[ "$VENV" =~ "dsvm-fullstack" ]]; then
        SECURE_PATH="$REPO_BASE/$PROJECT_NAME/neutron/tests/fullstack/agents:$SECURE_PATH"
    fi

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
Defaults:$STACK_USER  secure_path="$SECURE_PATH"
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

    if is_ubuntu; then
        install_package isc-dhcp-client
        install_package nmap
    elif is_fedora; then
        install_package dhclient
        install_package nmap-ncat
    elif is_suse; then
        install_package dhcp-client
        # NOTE(armax): no harm in allowing 'other' to read and
        # execute the script. This is required in fullstack
        # testing and avoids quite a bit of rootwrap pain
        sudo chmod o+rx /sbin/dhclient-script
        install_package ncat
    else
        exit_distro_not_supported "installing dhclient and ncat packages"
    fi

    enable_kernel_bridge_firewall

    # install/start memory tracker service if enabled
    if [[ "$MEMORY_TRACKER" == "True" ]]; then
        # is_service_enabled checks for service into ENABLED_SERVICES
        ENABLED_SERVICES+=,dstat,memory_tracker
        source $DEVSTACK_PATH/lib/dstat
        if is_ubuntu; then
            install_package pcp
        else
            install_package pcp-system-tools
        fi
        install_dstat
        start_dstat
    fi

    if [[ "$IS_GATE" != "True" ]]; then
        # Ensure home directory for the ``stack`` user has executable
        # permissions for all. Only for local (non-gate) installations.
        # Check https://review.opendev.org/c/openstack/devstack/+/838645
        chmod +x $HOME
    fi
}


function _configure_iptables_rules {
    # For linuxbridge agent fullstack tests we need to add special rules to
    # iptables for connection of agents to rabbitmq:
    CHAIN_NAME="openstack-INPUT"
    sudo iptables -n --list $CHAIN_NAME 1> /dev/null 2>&1 || CHAIN_NAME="INPUT"
    sudo iptables -I $CHAIN_NAME -s 240.0.0.0/8 -p tcp -m tcp -d 240.0.0.0/8 --dport 5672 -j ACCEPT
}


function _enable_ipv6 {
    sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
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
    if [[ "$INSTALL_MYSQL_ONLY" == "True" ]]; then
        _install_databases nopg
    else
        configure_host_for_func_testing
    fi
fi

if [[ "$VENV" =~ "dsvm-fullstack" ]]; then
    _enable_ipv6
    _configure_iptables_rules
    # This module only exists on older kernels, built-in otherwise
    modinfo ip_conntrack_proto_sctp 1> /dev/null 2>&1 && sudo modprobe ip_conntrack_proto_sctp
    if is_fedora; then
        install_package kernel-modules-extra-`uname -r`
        sudo modprobe sctp
    fi
fi

echo "Phew, we're done!"

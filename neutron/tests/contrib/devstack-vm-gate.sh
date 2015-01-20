#!/bin/bash

# Script that is run on the devstack vm; configures and
# invokes devstack.

# Copyright (C) 2011-2012 OpenStack LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit

# Keep track of the devstack directory
TOP_DIR=$(cd $(dirname "$0") && pwd)

# Prepare the environment
# -----------------------

# Import common functions
source $TOP_DIR/functions.sh

echo $PPID > $WORKSPACE/gate.pid
source `dirname "$(readlink -f "$0")"`/functions.sh

FIXED_RANGE=${DEVSTACK_GATE_FIXED_RANGE:-10.1.0.0/20}
FLOATING_RANGE=${DEVSTACK_GATE_FLOATING_RANGE:-172.24.4.0/24}

function setup_localrc {
    local localrc_oldnew=$1;
    local localrc_branch=$2;
    local localrc_file=$3
    local role=$4

    # Allow calling context to pre-populate the localrc file
    # with additional values
    if [[ -z $KEEP_LOCALRC ]] ; then
        rm -f $localrc_file
    fi

    # Install PyYaml for test-matrix.py
    if uses_debs; then
        sudo apt-get update
        sudo apt-get install python-yaml
    elif is_fedora; then
        sudo yum install -y PyYAML
    fi
    MY_ENABLED_SERVICES=`cd $BASE/new/devstack-gate && ./test-matrix.py -b $localrc_branch -f $DEVSTACK_GATE_FEATURE_MATRIX`
    local original_enabled_services=$MY_ENABLED_SERVICES

    # TODO(afazekas): Move to the feature grid
    # TODO(afazekas): add c-vol
    if [[ $role = sub ]]; then
        if [[ "$DEVSTACK_GATE_NEUTRON" -eq "1" ]]; then
            MY_ENABLED_SERVICES="q-agt,n-cpu,ceilometer-acompute"
        else
            MY_ENABLED_SERVICES="n-cpu,ceilometer-acompute"
        fi
    fi

    # Allow optional injection of ENABLED_SERVICES from the calling context
    if [[ ! -z $ENABLED_SERVICES ]] ; then
        MY_ENABLED_SERVICES+=,$ENABLED_SERVICES
    fi

    if [[ "$DEVSTACK_GATE_CEPH" == "1" ]]; then
        echo "CINDER_ENABLED_BACKENDS=ceph:ceph" >>"$localrc_file"
        echo "TEMPEST_STORAGE_PROTOCOL=ceph" >>"$localrc_file"
        echo "CEPH_LOOPBACK_DISK_SIZE=8G" >>"$localrc_file"
    fi

    # the exercises we *don't* want to test on for devstack
    SKIP_EXERCISES=boot_from_volume,bundle,client-env,euca

    if [[ "$DEVSTACK_GATE_NEUTRON" -eq "1" ]]; then
        echo "Q_USE_DEBUG_COMMAND=True" >>"$localrc_file"
        echo "NETWORK_GATEWAY=10.1.0.1" >>"$localrc_file"
    fi

    if [[ "$DEVSTACK_GATE_NEUTRON_DVR" -eq "1" ]]; then
        echo "Q_DVR_MODE=dvr_snat" >>"$localrc_file"
    fi

    cat <<EOF >>"$localrc_file"
USE_SCREEN=False
DEST=$BASE/$localrc_oldnew
# move DATA_DIR outside of DEST to keep DEST a bit cleaner
DATA_DIR=$BASE/data
ACTIVE_TIMEOUT=90
BOOT_TIMEOUT=90
ASSOCIATE_TIMEOUT=60
TERMINATE_TIMEOUT=60
MYSQL_PASSWORD=secretmysql
DATABASE_PASSWORD=secretdatabase
RABBIT_PASSWORD=secretrabbit
ADMIN_PASSWORD=secretadmin
SERVICE_PASSWORD=secretservice
SERVICE_TOKEN=111222333444
SWIFT_HASH=1234123412341234
ROOTSLEEP=0
ERROR_ON_CLONE=True
ENABLED_SERVICES=$MY_ENABLED_SERVICES
SKIP_EXERCISES=$SKIP_EXERCISES
SERVICE_HOST=127.0.0.1
# Screen console logs will capture service logs.
SYSLOG=False
SCREEN_LOGDIR=$BASE/$localrc_oldnew/screen-logs
LOGFILE=$BASE/$localrc_oldnew/devstacklog.txt
VERBOSE=True
FIXED_RANGE=$FIXED_RANGE
FLOATING_RANGE=$FLOATING_RANGE
FIXED_NETWORK_SIZE=4096
VIRT_DRIVER=$DEVSTACK_GATE_VIRT_DRIVER
SWIFT_REPLICAS=1
LOG_COLOR=False
PIP_USE_MIRRORS=False
USE_GET_PIP=1
# Don't reset the requirements.txt files after g-r updates
UNDO_REQUIREMENTS=False
# Set to soft if the project is using libraries not in g-r
REQUIREMENTS_MODE=${REQUIREMENTS_MODE}
CINDER_PERIODIC_INTERVAL=10
export OS_NO_CACHE=True
CEILOMETER_BACKEND=$DEVSTACK_GATE_CEILOMETER_BACKEND
LIBS_FROM_GIT=$DEVSTACK_PROJECT_FROM_GIT
ZAQAR_BACKEND=$DEVSTACK_GATE_ZAQAR_BACKEND
EOF

    if [[ "$DEVSTACK_CINDER_SECURE_DELETE" -eq "0" ]]; then
        echo "CINDER_SECURE_DELETE=False" >>"$localrc_file"
    fi

    if [[ "$DEVSTACK_GATE_TEMPEST_HEAT_SLOW" -eq "1" ]]; then
        echo "HEAT_CREATE_TEST_IMAGE=False" >>"$localrc_file"
        # Use Fedora 20 for heat test image, it has heat-cfntools pre-installed
        echo "HEAT_FETCHED_TEST_IMAGE=Fedora-i386-20-20131211.1-sda" >>"$localrc_file"
    fi

    if [[ "$DEVSTACK_GATE_VIRT_DRIVER" == "openvz" ]]; then
        echo "SKIP_EXERCISES=${SKIP_EXERCISES},volumes" >>"$localrc_file"
        echo "DEFAULT_INSTANCE_TYPE=m1.small" >>"$localrc_file"
        echo "DEFAULT_INSTANCE_USER=root" >>"$localrc_file"
        echo "DEFAULT_INSTANCE_TYPE=m1.small" >>exerciserc
        echo "DEFAULT_INSTANCE_USER=root" >>exerciserc
    fi

    if [[ "$DEVSTACK_GATE_VIRT_DRIVER" == "ironic" ]]; then
        echo "VIRT_DRIVER=ironic" >>"$localrc_file"
        echo "IRONIC_BAREMETAL_BASIC_OPS=True" >>"$localrc_file"
        echo "IRONIC_VM_LOG_DIR=$BASE/$localrc_oldnew/ironic-bm-logs" >>"$localrc_file"
        echo "DEFAULT_INSTANCE_TYPE=baremetal" >>"$localrc_file"
        echo "BUILD_TIMEOUT=300" >>"$localrc_file"
        if [[ "$DEVSTACK_GATE_IRONIC_BUILD_RAMDISK" -eq 0 ]]; then
            echo "IRONIC_BUILD_DEPLOY_RAMDISK=False" >>"$localrc_file"
        fi
        if [[ "$DEVSTACK_GATE_IRONIC_DRIVER" == "agent_ssh" ]]; then
            echo "SWIFT_ENABLE_TEMPURLS=True" >>"$localrc_file"
            echo "SWIFT_TEMPURL_KEY=secretkey" >>"$localrc_file"
            echo "IRONIC_ENABLED_DRIVERS=fake,agent_ssh,agent_ipmitool" >>"$localrc_file"
            echo "IRONIC_DEPLOY_DRIVER=agent_ssh" >>"$localrc_file"
            # agent driver doesn't support ephemeral volumes yet
            echo "IRONIC_VM_EPHEMERAL_DISK=0" >>"$localrc_file"
            # agent CoreOS ramdisk is a little heavy
            echo "IRONIC_VM_SPECS_RAM=1024" >>"$localrc_file"
            echo "IRONIC_VM_COUNT=1" >>"$localrc_file"
        else
            echo "IRONIC_VM_EPHEMERAL_DISK=1" >>"$localrc_file"
            echo "IRONIC_VM_COUNT=3" >>"$localrc_file"
        fi
    fi

    if [[ "$DEVSTACK_GATE_VIRT_DRIVER" == "xenapi" ]]; then
        if [ ! $DEVSTACK_GATE_XENAPI_DOM0_IP -o ! $DEVSTACK_GATE_XENAPI_DOMU_IP -o ! $DEVSTACK_GATE_XENAPI_PASSWORD ]; then
            echo "XenAPI must have DEVSTACK_GATE_XENAPI_DOM0_IP, DEVSTACK_GATE_XENAPI_DOMU_IP and DEVSTACK_GATE_XENAPI_PASSWORD all set"
            exit 1
        fi
        cat >> "$localrc_file" << EOF
SKIP_EXERCISES=${SKIP_EXERCISES},volumes
XENAPI_PASSWORD=${DEVSTACK_GATE_XENAPI_PASSWORD}
XENAPI_CONNECTION_URL=http://${DEVSTACK_GATE_XENAPI_DOM0_IP}
VNCSERVER_PROXYCLIENT_ADDRESS=${DEVSTACK_GATE_XENAPI_DOM0_IP}
VIRT_DRIVER=xenserver

# A separate xapi network is created with this name-label
FLAT_NETWORK_BRIDGE=vmnet

# A separate xapi network on eth4 serves the purpose of the public network
PUBLIC_INTERFACE=eth4

# The xapi network "vmnet" is connected to eth3 in domU
# We need to explicitly specify these, as the devstack/xenserver driver
# sets GUEST_INTERFACE_DEFAULT
VLAN_INTERFACE=eth3
FLAT_INTERFACE=eth3

# Explicitly set HOST_IP, so that it will be passed down to xapi,
# thus it will be able to reach glance
HOST_IP=${DEVSTACK_GATE_XENAPI_DOMU_IP}
SERVICE_HOST=${DEVSTACK_GATE_XENAPI_DOMU_IP}

# Disable firewall
XEN_FIREWALL_DRIVER=nova.virt.firewall.NoopFirewallDriver

# Disable agent
EXTRA_OPTS=("xenapi_disable_agent=True")

# Add a separate device for volumes
VOLUME_BACKING_DEVICE=/dev/xvdb

# Set multi-host config
MULTI_HOST=1
EOF
    fi

    if [[ "$DEVSTACK_GATE_TEMPEST" -eq "1" ]]; then
        # We need to disable ratelimiting when running
        # Tempest tests since so many requests are executed
        # TODO(mriedem): Remove this when stable/juno is our oldest
        # supported branch since devstack no longer uses it since Juno.
        echo "API_RATE_LIMIT=False" >> "$localrc_file"
        # Volume tests in Tempest require a number of volumes
        # to be created, each of 1G size. Devstack's default
        # volume backing file size is 10G.
        #
        # The 24G setting is expected to be enough even
        # in parallel run.
        echo "VOLUME_BACKING_FILE_SIZE=24G" >> "$localrc_file"
        # in order to ensure glance http tests don't time out, we
        # specify the TEMPEST_HTTP_IMAGE address to be horrizon's
        # front page. Kind of hacky, but it works.
        echo "TEMPEST_HTTP_IMAGE=http://127.0.0.1/static/dashboard/img/favicon.ico" >> "$localrc_file"
    fi

    if [[ "$DEVSTACK_GATE_TEMPEST_DISABLE_TENANT_ISOLATION" -eq "1" ]]; then
        echo "TEMPEST_ALLOW_TENANT_ISOLATION=False" >>"$localrc_file"
    fi

    if [[ -n "$DEVSTACK_GATE_GRENADE" ]]; then
        if [[ "$localrc_old" == "old" ]]; then
            echo "GRENADE_PHASE=base" >> "$localrc_file"
        else
            echo "GRENADE_PHASE=target" >> "$localrc_file"
        fi
        # keystone deployed with mod wsgi cannot be upgraded or migrated
        # until https://launchpad.net/bugs/1365105 is resolved.
        echo "KEYSTONE_USE_MOD_WSGI=False" >> "$localrc_file"
    fi

    if [[ "$DEVSTACK_GATE_TEMPEST_LARGE_OPS" -eq "1" ]]; then
        # NOTE(danms): Temporary transition to =NUM_RESOURCES
        echo "VIRT_DRIVER=fake" >> "$localrc_file"
        echo "TEMPEST_LARGE_OPS_NUMBER=50" >>"$localrc_file"
    elif [[ "$DEVSTACK_GATE_TEMPEST_LARGE_OPS" -gt "1" ]]; then
        # use fake virt driver and 10 copies of nova-compute
        echo "VIRT_DRIVER=fake" >> "$localrc_file"
        # To make debugging easier, disabled until bug 1218575 is fixed.
        # echo "NUMBER_FAKE_NOVA_COMPUTE=10" >>"$localrc_file"
        echo "TEMPEST_LARGE_OPS_NUMBER=$DEVSTACK_GATE_TEMPEST_LARGE_OPS" >>"$localrc_file"

    fi

    if [[ "$DEVSTACK_GATE_CONFIGDRIVE" -eq "1" ]]; then
        echo "FORCE_CONFIG_DRIVE=always" >>"$localrc_file"
    else
        echo "FORCE_CONFIG_DRIVE=False" >>"$localrc_file"
    fi
    if [[ "$DEVSTACK_GATE_KEYSTONE_V3" -eq "1" ]]; then
        # Run gate using only keystone v3
        # For now this is only injected in tempest configuration
        echo "TEMPEST_AUTH_VERSION=v3" >>"$localrc_file"
    fi

    if [[ "$DEVSTACK_GATE_ENABLE_HTTPD_MOD_WSGI_SERVICES" -eq "0" ]]; then
        # Services that default to run under Apache + mod_wsgi will use alternatives
        # (e.g. Keystone under eventlet) if available. This will affect all services
        # that run under HTTPD (mod_wsgi) by default.
        echo "ENABLE_HTTPD_MOD_WSGI_SERVICES=False" >> "$localrc_file"
    fi

    if [[ "$CEILOMETER_NOTIFICATION_TOPICS" ]]; then
        # Add specified ceilometer notification topics to localrc
        # Set to notifications,profiler to enable profiling
        echo "CEILOMETER_NOTIFICATION_TOPICS=$CEILOMETER_NOTIFICATION_TOPICS" >>"$localrc_file"
    fi

    if [[ "$DEVSTACK_GATE_NOVA_REPLACE_V2_ENDPOINT_WITH_V21_API" -eq "1" ]]; then
        echo "NOVA_API_VERSION=v21default" >> "$localrc_file"
    fi

    if [[ "$DEVSTACK_GATE_INSTALL_TESTONLY" -eq "1" ]]; then
        # Sometimes we do want the test packages
        echo "INSTALL_TESTONLY_PACKAGES=True" >> "$localrc_file"
    fi

    if [[ "$DEVSTACK_GATE_TOPOLOGY" != "aio" ]]; then
        echo "NOVA_ALLOW_MOVE_TO_SAME_HOST=False" >> "$localrc_file"
        local primary_node=`cat /etc/nodepool/primary_node_private`
        echo "SERVICE_HOST=$primary_node" >>"$localrc_file"

        if [[ "$role" = sub ]]; then
            if [[ $original_enabled_services  =~ "qpid" ]]; then
                echo "QPID_HOST=$primary_node" >>"$localrc_file"
            fi
            if [[ $original_enabled_services =~ "rabbit" ]]; then
                echo "RABBIT_HOST=$primary_node" >>"$localrc_file"
            fi
            echo "DATABASE_HOST=$primary_node" >>"$localrc_file"
            if [[ $original_enabled_services =~ "mysql" ]]; then
                 echo "DATABASE_TYPE=mysql"  >>"$localrc_file"
            else
                 echo "DATABASE_TYPE=postgresql"  >>"$localrc_file"
            fi
            echo "GLANCE_HOSTPORT=$primary_node:9292" >>"$localrc_file"
            echo "Q_HOST=$primary_node" >>"$localrc_file"
            # Set HOST_IP in subnodes before copying localrc to each node
        else
            echo "HOST_IP=$primary_node" >>"$localrc_file"
        fi
    fi

    # a way to pass through arbitrary devstack config options so that
    # we don't need to add new devstack-gate options every time we
    # want to create a new config.
    if [[ -n "$DEVSTACK_LOCAL_CONFIG" ]]; then
        echo "$DEVSTACK_LOCAL_CONFIG" >>"$localrc_file"
    fi

}

if [[ -n "$DEVSTACK_GATE_GRENADE" ]]; then
    if [[ "$DEVSTACK_GATE_GRENADE" == "sideways-ironic" ]]; then
        # Disable ironic when generating the "old" localrc.
        TMP_DEVSTACK_GATE_IRONIC=$DEVSTACK_GATE_IRONIC
        TMP_DEVSTACK_GATE_VIRT_DRIVER=$DEVSTACK_GATE_VIRT_DRIVER
        export DEVSTACK_GATE_IRONIC=0
        export DEVSTACK_GATE_VIRT_DRIVER="fake"
    fi
    if [[ "$DEVSTACK_GATE_GRENADE" == "sideways-neutron" ]]; then
        # Use nova network when generating "old" localrc.
        TMP_DEVSTACK_GATE_NEUTRON=$DEVSTACK_GATE_NEUTRON
        export DEVSTACK_GATE_NEUTRON=0
    fi
    cd $BASE/old/devstack
    setup_localrc "old" "$GRENADE_OLD_BRANCH" "localrc" "primary"

    if [[ "$DEVSTACK_GATE_GRENADE" == "sideways-ironic" ]]; then
        # Set ironic and virt driver settings to those initially set
        # by the job.
        export DEVSTACK_GATE_IRONIC=$TMP_DEVSTACK_GATE_IRONIC
        export DEVSTACK_GATE_VIRT_DRIVER=$TMP_DEVSTACK_GATE_VIRT_DRIVER
    fi
    if [[ "$DEVSTACK_GATE_GRENADE" == "sideways-neutron" ]]; then
        # Set neutron setting to that initially set by the job.
        export DEVSTACK_GATE_NEUTRON=$TMP_DEVSTACK_GATE_NEUTRON
    fi
    cd $BASE/new/devstack
    setup_localrc "new" "$GRENADE_OLD_BRANCH" "localrc" "primary"

    cat <<EOF >$BASE/new/grenade/localrc
BASE_RELEASE=old
BASE_RELEASE_DIR=$BASE/\$BASE_RELEASE
BASE_DEVSTACK_DIR=\$BASE_RELEASE_DIR/devstack
BASE_DEVSTACK_BRANCH=$GRENADE_OLD_BRANCH
TARGET_RELEASE=new
TARGET_RELEASE_DIR=$BASE/\$TARGET_RELEASE
TARGET_DEVSTACK_DIR=\$TARGET_RELEASE_DIR/devstack
TARGET_DEVSTACK_BRANCH=$GRENADE_NEW_BRANCH
TARGET_RUN_SMOKE=False
SAVE_DIR=\$BASE_RELEASE_DIR/save
DO_NOT_UPGRADE_SERVICES=$DO_NOT_UPGRADE_SERVICES
TEMPEST_CONCURRENCY=$TEMPEST_CONCURRENCY
VERBOSE=False
EOF

    if [[ "$DEVSTACK_GATE_GRENADE" == "sideways-ironic" ]]; then
        # sideways-ironic migrates from a fake environment, avoid exercising
        # base.
        echo "BASE_RUN_SMOKE=False" >> $BASE/new/grenade/localrc
        echo "RUN_JAVELIN=False" >> $BASE/new/grenade/localrc
    fi

    # Make the workspace owned by the stack user
    sudo chown -R stack:stack $BASE

    cd $BASE/new/grenade
    echo "Running grenade ..."
    echo "This takes a good 30 minutes or more"
    sudo -H -u stack stdbuf -oL -eL ./grenade.sh
    cd $BASE/new/devstack

else
    cd $BASE/new/devstack
    setup_localrc "new" "$OVERRIDE_ZUUL_BRANCH" "localrc" "primary"

    if [[ "$DEVSTACK_GATE_TOPOLOGY" != "aio" ]]; then
        set -x  # for now enabling debug and do not turn it off
        setup_localrc "new" "$OVERRIDE_ZUUL_BRANCH" "sub_localrc" "sub"
        sudo mkdir -p $BASE/new/.ssh
        sudo cp /etc/nodepool/id_rsa.pub $BASE/new/.ssh/authorized_keys
        sudo cp /etc/nodepool/id_rsa $BASE/new/.ssh/
        sudo chmod 600 $BASE/new/.ssh/authorized_keys
        sudo chmod 400 $BASE/new/.ssh/id_rsa
        for NODE in `cat /etc/nodepool/sub_nodes_private`; do
            echo "Copy Files to  $NODE"
            remote_copy_dir $NODE $BASE/new/devstack-gate $WORKSPACE
            remote_copy_file $WORKSPACE/test_env.sh $NODE:$WORKSPACE/test_env.sh
            echo "Preparing $NODE"
            remote_command $NODE "source $WORKSPACE/test_env.sh; $WORKSPACE/devstack-gate/sub_node_prepare.sh"
            remote_copy_file /etc/nodepool/id_rsa "$NODE:$BASE/new/.ssh/"
            remote_command $NODE sudo chmod 400 "$BASE/new/.ssh/*"
        done
        PRIMARY_NODE=`cat /etc/nodepool/primary_node_private`
        SUB_NODES=`cat /etc/nodepool/sub_nodes_private`
        NODES="$PRIMARY_NODE $SUB_NODES"
        if [[ "$DEVSTACK_GATE_NEUTRON" -ne '1' ]]; then
            (source $BASE/new/devstack/functions-common; install_package bridge-utils)
            gre_bridge "pub_if" 1 $NODES
            cat <<EOF >>"$BASE/new/devstack/sub_localrc"
FLAT_INTERFACE=pub_if
PUBLIC_INTERFACE=pub_if
EOF
            cat <<EOF >>"$BASE/new/devstack/localrc"
FLAT_INTERFACE=pub_if
PUBLIC_INTERFACE=pub_if
EOF
        fi
    fi
    # Make the workspace owned by the stack user
    sudo chown -R stack:stack $BASE

    echo "Running devstack"
    echo "... this takes 5 - 8 minutes (logs in logs/devstacklog.txt.gz)"
    start=$(date +%s)
    sudo -H -u stack stdbuf -oL -eL ./stack.sh > /dev/null
    end=$(date +%s)
    took=$((($end - $start) / 60))
    if [[ "$took" -gt 15 ]]; then
        echo "WARNING: devstack run took > 15 minutes, this is a very slow node."
    fi

    # provide a check that the right db was running
    # the path are different for fedora and red hat.
    if [[ -f /usr/bin/yum ]]; then
        POSTGRES_LOG_PATH="-d /var/lib/pgsql"
        MYSQL_LOG_PATH="-f /var/log/mysqld.log"
    else
        POSTGRES_LOG_PATH="-d /var/log/postgresql"
        MYSQL_LOG_PATH="-d /var/log/mysql"
    fi
    if [[ "$DEVSTACK_GATE_POSTGRES" -eq "1" ]]; then
        if [[ ! $POSTGRES_LOG_PATH ]]; then
            echo "Postgresql should have been used, but there are no logs"
            exit 1
        fi
    else
        if [[ ! $MYSQL_LOG_PATH ]]; then
            echo "Mysql should have been used, but there are no logs"
            exit 1
        fi
    fi

    if [[ "$DEVSTACK_GATE_TOPOLOGY" != "aio" ]]; then
        echo "Preparing cross node connectivity"
        for NODE in `cat /etc/nodepool/sub_nodes_private`; do
            echo "Running devstack on $NODE"
            sudo cp sub_localrc tmp_sub_localrc
            echo "HOST_IP=$NODE" | sudo tee --append tmp_sub_localrc > /dev/null
            remote_copy_file tmp_sub_localrc $NODE:$BASE/new/devstack/localrc
            remote_command $NODE sudo chown -R stack:stack $BASE
            remote_command $NODE "cd $BASE/new/devstack; source $WORKSPACE/test_env.sh; export -n PROJECTS; sudo -H -u stack stdbuf -oL -eL ./stack.sh > /dev/null"
        done

       if [[ $DEVSTACK_GATE_NEUTRON -eq "1" ]]; then
            # NOTE(afazekas): The cirros lp#1301958 does not support MTU setting via dhcp,
            # simplest way the have tunneling working, with dvsm, without increasing the host system MTU
            # is to decreasion the MTU on br-ex
            # TODO(afazekas): Configure the mtu smarter on the devstack side
            sudo ip link set mtu 1450 dev br-ex
        fi
    fi
fi

if [[ "$DEVSTACK_GATE_UNSTACK" -eq "1" ]]; then
   sudo -H -u stack ./unstack.sh
fi

echo "Removing sudo privileges for devstack user"
sudo rm /etc/sudoers.d/50_stack_sh

if [[ "$DEVSTACK_GATE_EXERCISES" -eq "1" ]]; then
    echo "Running devstack exercises"
    sudo -H -u stack ./exercise.sh
fi

if [[ "$DEVSTACK_GATE_TEMPEST" -eq "1" ]]; then
    # under tempest isolation tempest will need to write .tox dir, log files
    if [[ -d "$BASE/new/tempest" ]]; then
        sudo chown -R tempest:stack $BASE/new/tempest
    fi

    # Make sure tempest user can write to its directory for
    # lock-files.
    if [[ -d $BASE/data/tempest ]]; then
        sudo chown -R tempest:stack $BASE/data/tempest
    fi
    # ensure the cirros image files are accessible
    if [[ -d /opt/stack/new/devstack/files ]]; then
        sudo chmod -R o+rx /opt/stack/new/devstack/files
    fi

    # We don't need to run Tempest, if this is switched on
    if [[ "$DEVSTACK_GATE_TEMPEST_INSTALL_ONLY" -eq "1" ]]; then
        exit 0
    fi
    # From here until the end we rely on the fact that all the code fails if
    # something is wrong, to enforce exit on bad test results.
    set -o errexit

    cd $BASE/new/tempest
    if [[ "$DEVSTACK_GATE_TEMPEST_REGEX" != "" ]] ; then
        echo "Running tempest with a custom regex filter"
        sudo -H -u tempest tox -eall -- --concurrency=$TEMPEST_CONCURRENCY $DEVSTACK_GATE_TEMPEST_REGEX
    elif [[ "$DEVSTACK_GATE_TEMPEST_ALL" -eq "1" ]]; then
        echo "Running tempest all test suite"
        sudo -H -u tempest tox -eall -- --concurrency=$TEMPEST_CONCURRENCY
    elif [[ "$DEVSTACK_GATE_TEMPEST_DISABLE_TENANT_ISOLATION" -eq "1" ]]; then
        echo "Running tempest full test suite serially"
        sudo -H -u tempest tox -efull-serial
    elif [[ "$DEVSTACK_GATE_TEMPEST_FULL" -eq "1" ]]; then
        echo "Running tempest full test suite"
        sudo -H -u tempest tox -efull -- --concurrency=$TEMPEST_CONCURRENCY
    elif [[ "$DEVSTACK_GATE_TEMPEST_STRESS" -eq "1" ]] ; then
        echo "Running stress tests"
        sudo -H -u tempest tox -estress -- -d 3600 -S -s -t tempest/stress/etc/stress-tox-job.json
    elif [[ "$DEVSTACK_GATE_TEMPEST_HEAT_SLOW" -eq "1" ]] ; then
        echo "Running slow heat tests"
        sudo -H -u tempest tox -eheat-slow -- --concurrency=$TEMPEST_CONCURRENCY
    elif [[ "$DEVSTACK_GATE_TEMPEST_LARGE_OPS" -ge "1" ]] ; then
        echo "Running large ops tests"
        sudo -H -u tempest tox -elarge-ops -- --concurrency=$TEMPEST_CONCURRENCY
    elif [[ "$DEVSTACK_GATE_SMOKE_SERIAL" -eq "1" ]] ; then
        echo "Running tempest smoke tests"
        sudo -H -u tempest tox -esmoke-serial
    else
        echo "Running tempest smoke tests"
        sudo -H -u tempest tox -esmoke -- --concurrency=$TEMPEST_CONCURRENCY
    fi

fi

#!/bin/bash

# Copyright 2018 Red Hat, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# With LANG set to everything else than C completely undercipherable errors
# like "file not found" and decoding errors will start to appear during scripts
# or even ansible modules
LANG=C

# Complete stackrc file path.
: ${STACKRC_FILE:=~/stackrc}

# Complete overcloudrc file path.
: ${OVERCLOUDRC_FILE:=~/overcloudrc}

# overcloud deploy script for OVN migration.
: ${OVERCLOUD_OVN_DEPLOY_SCRIPT:=~/overcloud-deploy-ovn.sh}

# user on the nodes in the undercloud
: ${UNDERCLOUD_NODE_USER:=heat-admin}

: ${OPT_WORKDIR:=$PWD}
: ${STACK_NAME:=overcloud}
: ${OOO_WORKDIR:=$HOME/overcloud-deploy}
: ${PUBLIC_NETWORK_NAME:=public}
: ${IMAGE_NAME:=cirros}
: ${FLAVOR_NAME:=ovn-migration}
: ${SERVER_USER_NAME:=cirros}
: ${VALIDATE_MIGRATION:=False}
: ${DHCP_RENEWAL_TIME:=30}
: ${CREATE_BACKUP:=True}
: ${BACKUP_MIGRATION_IP:=192.168.24.1} # TODO: Document this new var


check_for_necessary_files() {
    if [ ! -e hosts_for_migration ]; then
        echo "hosts_for_migration ansible inventory file not present"
        echo "Please run ./ovn_migration.sh generate-inventory"
        exit 1
    fi

    # Check if the user has generated overcloud-deploy-ovn.sh file
    # With correct permissions
    # If it is not generated. Exit
    if [ ! -x $OVERCLOUD_OVN_DEPLOY_SCRIPT ]; then
        echo "overcloud deploy migration script :" \
             "$OVERCLOUD_OVN_DEPLOY_SCRIPT is not present" \
             "or execution permission is missing. Please" \
             "make sure you create that file with correct" \
             "permissions before running this script."
        exit 1
    fi

    grep -q -- '--answers-file'  $OVERCLOUD_OVN_DEPLOY_SCRIPT || grep -q -- '--environment-directory'  $OVERCLOUD_OVN_DEPLOY_SCRIPT
    answers_templates_check=$?

    grep -q -- 'neutron-ovn' $OVERCLOUD_OVN_DEPLOY_SCRIPT
    if [[ $? -eq 1 ]]; then
        if [[ $answers_templates_check -eq 0 ]]; then
            echo -e "\nWARNING!!! You are using an answers-file or a templates directory" \
                    " ( --answers-file/--environment-directory) " \
                    "\nYou MUST make sure the proper OVN files are included in the templates called by your deploy script"
        else
            echo -e "OVN t-h-t environment file(s) seems to be missing in " \
                "$OVERCLOUD_OVN_DEPLOY_SCRIPT. Please check the $OVERCLOUD_OVN_DEPLOY_SCRIPT" \
                "file again."
            exit 1
        fi
    fi

    grep -q \$HOME/ovn-extras.yaml $OVERCLOUD_OVN_DEPLOY_SCRIPT
    check1=$?
    grep -q $HOME/ovn-extras.yaml $OVERCLOUD_OVN_DEPLOY_SCRIPT
    check2=$?

    if [[ $check1 -eq 1 && $check2 -eq 1 ]]; then
        # specific case of --answers-file/--environment-directory
        if [[ $answers_templates_check -eq 0 ]]; then
            echo -e "\nWARNING!!! You are using an answers-file or a templates directory" \
                 " ( --answers-file/--environment-directory) " \
                 "\nYou MUST add ovn-extras.yaml to your new set of templates for OVN-based deploys." \
                 "\n  e.g: add \" -e \$HOME/ovn-extras.yaml \" to the deploy command in $OVERCLOUD_OVN_DEPLOY_SCRIPT" \
                 "\nOnce OVN migration is finished, ovn-extras.yaml can then be safely removed from your OVN templates."
        else
            echo "ovn-extras.yaml file is missing in "\
                 "$OVERCLOUD_OVN_DEPLOY_SCRIPT. Please add it "\
                 "as \" -e \$HOME/ovn-extras.yaml\""
        fi
        exit 1
    fi
    # Check if backup is enabled
    if [[ $CREATE_BACKUP = True ]]; then
        # Check if backup server is reachable
        ping -c4 $BACKUP_MIGRATION_IP
        if [[ $? -eq 1 ]]; then
            echo -e "It is not possible to reach the backup migration server IP" \
                    "($BACKUP_MIGRATION_IP). Make sure this IP is accessible before" \
                    "starting the migration." \
                    "Change this value by doing: export BACKUP_MIGRATION_IP=x.x.x.x"
        fi
    fi
}

get_host_ip() {
    inventory_file=$1
    host_name=$2
    host_vars=$(ansible-inventory -i "$inventory_file" --host "$host_name" 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        echo "$host_vars" | jq -r \.ansible_host
    else
        echo $host_name
    fi
}

get_group_hosts() {
    inventory_file=$1
    group_name=$2
    group_graph=$(ansible-inventory -i "$inventory_file" --graph "$group_name" 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        echo "$group_graph" | sed -ne 's/^[ \t|]\+--\([a-z0-9\-]\+\)$/\1/p'
    else
        echo ""
    fi
}

# Generate the ansible.cfg file
generate_ansible_config_file() {

    cat > ansible.cfg <<-EOF
[defaults]
forks=50
become=True
callback_whitelist = profile_tasks
host_key_checking = False
gathering = smart
fact_caching = jsonfile
fact_caching_connection = ./ansible_facts_cache
fact_caching_timeout = 0
log_path = $HOME/ovn_migration_ansible.log

#roles_path = roles:...

[ssh_connection]
control_path = %(directory)s/%%h-%%r
ssh_args = -o ControlMaster=auto -o ControlPersist=270s -o ServerAliveInterval=30 -o GSSAPIAuthentication=no
retries = 3

EOF
}

# Generate the inventory file for ansible migration playbook.
# It uses tripleo-ansible-inventory.yaml which was used during deployment as source inventory
generate_ansible_inventory_file() {
    local dhcp_nodes
    local inventory_file="$OOO_WORKDIR/$STACK_NAME/config-download/$STACK_NAME/tripleo-ansible-inventory.yaml"

    echo "Generating the inventory file for ansible-playbook"
    echo "[ovn-dbs]"  > hosts_for_migration
    ovn_central=True
    # We want to run ovn_dbs where neutron_api is running
    OVN_DBS=$(get_group_hosts "$inventory_file" neutron_api)
    for node_name in $OVN_DBS; do
        node_ip=$(get_host_ip "$inventory_file" $node_name)
        node="$node_name ansible_host=$node_ip"
        if [ "$ovn_central" == "True" ]; then
            ovn_central=False
            node="$node_name ansible_host=$node_ip ovn_central=true"
        fi
        echo $node ansible_ssh_user=$UNDERCLOUD_NODE_USER ansible_become=true >> hosts_for_migration
    done

    echo "" >> hosts_for_migration
    echo "[ovn-controllers]" >> hosts_for_migration

    # We want to run ovn-controller where OVS agent was running before the migration
    OVN_CONTROLLERS=$(get_group_hosts "$inventory_file" neutron_ovs_agent; get_group_hosts "$inventory_file" neutron_ovs_dpdk_agent)
    for node_name in $OVN_CONTROLLERS; do
        node_ip=$(get_host_ip "$inventory_file" $node_name)
        echo $node_name ansible_host=$node_ip ansible_ssh_user=$UNDERCLOUD_NODE_USER ansible_become=true ovn_controller=true >> hosts_for_migration
    done

    echo "" >> hosts_for_migration
    echo "[dhcp]" >> hosts_for_migration
    dhcp_nodes=$(get_group_hosts "$inventory_file" neutron_dhcp)
    for node_name in $dhcp_nodes; do
        node_ip=$(get_host_ip "$inventory_file" $node_name)
        echo $node_name ansible_host=$node_ip ansible_ssh_user=$UNDERCLOUD_NODE_USER ansible_become=true >> hosts_for_migration
    done

    echo "" >> hosts_for_migration

    cat >> hosts_for_migration << EOF

[overcloud-controllers:children]
dhcp

[overcloud:children]
ovn-controllers
ovn-dbs

EOF
    add_group_vars() {

    cat >> hosts_for_migration << EOF

[$1:vars]
remote_user=$UNDERCLOUD_NODE_USER
public_network_name=$PUBLIC_NETWORK_NAME
image_name=$IMAGE_NAME
flavor_name=$FLAVOR_NAME
working_dir=$OPT_WORKDIR
server_user_name=$SERVER_USER_NAME
validate_migration=$VALIDATE_MIGRATION
overcloud_ovn_deploy_script=$OVERCLOUD_OVN_DEPLOY_SCRIPT
overcloudrc=$OVERCLOUDRC_FILE
ovn_migration_backups=/var/lib/ovn-migration-backup
EOF
    }

    add_group_vars overcloud
    add_group_vars overcloud-controllers


    echo "***************************************"
    cat hosts_for_migration
    echo "***************************************"
    echo "Generated the inventory file - hosts_for_migration"
    echo "Please review the file before running the next command - reduce-dhcp-t1"
}

# Check if source inventory exists
function check_source_inventory {
    local inventory_file="$OOO_WORKDIR/$STACK_NAME/config-download/$STACK_NAME/tripleo-ansible-inventory.yaml"
    if [ ! -f $inventory_file ]; then
        echo "ERROR: Source Inventory File ${inventory_file} does not exist. Please provide the Stack Name and TripleO Workdir"
        echo "       via STACK_NAME and OOO_WORKDIR environment variables."
        exit 1
    fi
}

# Check if the public network exists, and if it has floating ips available

oc_check_public_network() {

    [ "$VALIDATE_MIGRATION" != "True" ] && return 0
    source $OVERCLOUDRC_FILE
    openstack network show $PUBLIC_NETWORK_NAME 1>/dev/null || {
        echo "ERROR: PUBLIC_NETWORK_NAME=${PUBLIC_NETWORK_NAME} can't be accessed by the"
        echo "       admin user, please fix that before continuing."
        exit 1
    }

    ID=$(openstack floating ip create $PUBLIC_NETWORK_NAME -c id -f value) || {
        echo "ERROR: PUBLIC_NETWORK_NAME=${PUBLIC_NETWORK_NAME} doesn't have available"
        echo "       floating ips. Make sure that your public network has at least one"
        echo "       floating ip available for the admin user."
        exit 1
    }

    openstack floating ip delete $ID 2>/dev/null 1>/dev/null
    return $?
}


# Check if the neutron networks MTU has been updated to geneve MTU size or not.
# We donot want to proceed if the MTUs are not updated.
oc_check_network_mtu() {
    source $OVERCLOUDRC_FILE
    neutron-ovn-migration-mtu verify mtu
    return $?
}

reduce_dhcp_t1() {
    # Run the ansible playbook to reduce the DHCP T1 parameter in
    # dhcp_agent.ini in all the overcloud nodes where dhcp agent is running.
    ansible-playbook  -vv $OPT_WORKDIR/playbooks/reduce-dhcp-renewal-time.yml \
        -i hosts_for_migration -e working_dir=$OPT_WORKDIR \
        -e renewal_time=$DHCP_RENEWAL_TIME
    rc=$?
    return $rc
}

reduce_network_mtu () {
    source $OVERCLOUDRC_FILE
    oc_check_network_mtu
    if [ "$?" != "0" ]; then
        # Reduce the network mtu
        neutron-ovn-migration-mtu update mtu
        rc=$?

        if [ "$rc" != "0" ]; then
            echo "Reducing the network mtu's failed. Exiting."
            exit 1
        fi
    fi

    return $rc
}

start_migration() {
    source $STACKRC_FILE
    echo "Starting the Migration"
    local inventory_file="$OOO_WORKDIR/$STACK_NAME/config-download/$STACK_NAME/tripleo-ansible-inventory.yaml"
    if ! test -f $inventory_file; then
        inventory_file=''
    fi
    ansible-playbook  -vv $OPT_WORKDIR/playbooks/ovn-migration.yml \
    -i hosts_for_migration -e working_dir=$OPT_WORKDIR \
    -e public_network_name=$PUBLIC_NETWORK_NAME \
    -e image_name=$IMAGE_NAME \
    -e flavor_name=$FLAVOR_NAME \
    -e undercloud_node_user=$UNDERCLOUD_NODE_USER \
    -e overcloud_ovn_deploy_script=$OVERCLOUD_OVN_DEPLOY_SCRIPT \
    -e server_user_name=$SERVER_USER_NAME \
    -e overcloudrc=$OVERCLOUDRC_FILE \
    -e stackrc=$STACKRC_FILE \
    -e backup_migration_ip=$BACKUP_MIGRATION_IP \
    -e create_backup=$CREATE_BACKUP \
    -e ansible_inventory=$inventory_file \
    -e validate_migration=$VALIDATE_MIGRATION $*

    rc=$?
    return $rc
}

print_usage() {

cat << EOF

Usage:

  Before running this script, please refer to the migration guide for
complete details. This script needs to be run in 5 steps.

 Step 1 -> ovn_migration.sh generate-inventory

           Generates the inventory file

 Step 2 -> ovn_migration.sh reduce-dhcp-t1 (deprecated name setup-mtu-t1)

           Sets the DHCP renewal T1 to 30 seconds. After this step you will
           need to wait at least 24h for the change to be propagated to all
           VMs. This step is only necessary for VXLAN or GRE based tenant
           networking.

 Step 3 -> You need to wait at least 24h based on the default configuration
           of neutron for the DHCP T1 parameter to be propagated, please
           refer to documentation. WARNING: this is very important if you
           are using VXLAN or GRE tenant networks.

 Step 4 -> ovn_migration.sh reduce-mtu

           Reduces the MTU of the neutron tenant networks networks. This
           step is only necessary for VXLAN or GRE based tenant networking.

 Step 5 -> ovn_migration.sh start-migration

           Starts the migration to OVN.

EOF

}

command=$1

ret_val=0
case $command in
    generate-inventory)
        check_source_inventory
        oc_check_public_network
        generate_ansible_inventory_file
        generate_ansible_config_file
        ret_val=$?
        ;;

    reduce-dhcp-t1 | setup-mtu-t1)
        if [[ $command = 'setup-mtu-t1' ]]; then
            echo -e "Warning: setup-mtu-t1 argument was renamed."\
                    "Use reduce-dhcp-t1 argument instead."
        fi
        check_for_necessary_files
        reduce_dhcp_t1
        ret_val=$?;;

    reduce-mtu)
        check_for_necessary_files
        reduce_network_mtu
        ret_val=$?;;

    start-migration)
        oc_check_public_network
        check_for_necessary_files
        shift
        start_migration $*
        ret_val=$?
        ;;

    *)
        print_usage;;
esac

exit $ret_val

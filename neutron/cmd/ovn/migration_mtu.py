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

import os
import sys

from neutron_lib import constants
from openstack import connection


# Overhead size of Geneve is configurable, use the recommended value
GENEVE_ENCAP_OVERHEAD = 38
# map of network types to migrate and the difference in overhead size when
# converted to Geneve.
NETWORK_TYPE_OVERHEAD_DIFF = {
    'vxlan': GENEVE_ENCAP_OVERHEAD - constants.VXLAN_ENCAP_OVERHEAD,
    'gre': GENEVE_ENCAP_OVERHEAD - constants.GRE_ENCAP_OVERHEAD,
}


def get_connection():
    """Get OpenStack SDK Connection object with parameters from environment.

    Project scoped authorization is used and the following environment
    variables are required:

        OS_AUTH_URL     URL to OpenStack Identity service
        OS_PROJECT_NAME Name of project for authorization
        OS_USERNAME     Username for authentication
        OS_PASSWORD     Password for authentication

    Which domain to use for authentication and authorization may be specified
    by domain name or domain ID. If none of the domain selection variables are
    set the tool will default to use the domain with literal ID of 'default'.

    To select domain by name set both of these environment variables:

        OS_USER_DOMAIN_NAME    Name of domain to authenticate to
        OS_PROJECT_DOMAIN_NAME Name of domain for authorization

    To select domain by ID set both of these environment variables:

        OS_USER_DOMAIN_ID    ID of domain to authenticate to
        OS_PROJECT_DOMAIN_ID ID of domain for authorization

    NOTE: If both OS_*_DOMAIN_NAME and OS_*_DOMAIN_ID variables are present in
    the environment the OS_*_DOMAIN_NAME variables will be used.
    """
    user_domain_name = os.environ.get('OS_USER_DOMAIN_NAME')
    project_domain_name = os.environ.get('OS_PROJECT_DOMAIN_NAME')
    user_domain_id = os.environ.get(
        'OS_USER_DOMAIN_ID',
        'default') if not user_domain_name else None
    project_domain_id = os.environ.get(
        'OS_PROJECT_DOMAIN_ID',
        'default') if not project_domain_name else None
    conn = connection.Connection(auth_url=os.environ['OS_AUTH_URL'],
                                 project_name=os.environ['OS_PROJECT_NAME'],
                                 username=os.environ['OS_USERNAME'],
                                 password=os.environ['OS_PASSWORD'],
                                 user_domain_id=user_domain_id,
                                 project_domain_id=project_domain_id,
                                 user_domain_name=user_domain_name,
                                 project_domain_name=project_domain_name)
    return conn


def verify_network_mtu():
    print("Verifying the tenant network mtu's")
    conn = get_connection()
    success = True
    for network in conn.network.networks():
        if network.provider_physical_network is None and (
                network.provider_network_type in
                NETWORK_TYPE_OVERHEAD_DIFF) and (
                    'adapted_mtu' not in network.tags):
            print("adapted_mtu tag is not set for the Network "
                  "[" + str(network.name) + "]")
            success = False

    if success:
        print("All the networks are set to expected mtu value")
    else:
        print("Some tenant networks need to have their MTU updated to a "
              "lower value.")
    return success


def update_network_mtu():
    print("Updating the tenant network mtu")
    conn = get_connection()
    for network in conn.network.networks():
        try:
            if network.provider_physical_network is None and (
                    network.provider_network_type in
                    NETWORK_TYPE_OVERHEAD_DIFF) and (
                        'adapted_mtu' not in network.tags):
                print("Updating the mtu and the tag 'adapted_mtu"
                      " of the network - " + str(network.name))
                new_tags = list(network.tags)
                new_tags.append('adapted_mtu')
                conn.network.update_network(
                    network,
                    mtu=int(network.mtu) - NETWORK_TYPE_OVERHEAD_DIFF[
                        network.provider_network_type])
                conn.network.set_tags(network, new_tags)
        except Exception as e:
            print("Exception occurred while updating the MTU:" + str(e))
            return False
    return True


def print_usage():
    print('Invalid options:')
    print('Usage: %s <update|verify> mtu' % sys.argv[0])


def main():
    """Tool for updating the networks MTU's pre migration.

    This lowers the MTU of the pre migration VXLAN and GRE networks. The
    tool will ignore non-VXLAN/GRE networks, so if you use VLAN for tenant
    networks it will be fine if you find this step not doing anything.

    This step will go network by network reducing the MTU, and tagging
    with adapted_mtu the networks which have been already handled.

    Every time a network is updated all the existing L3/DHCP agents
    connected to such network will update their internal leg MTU,
    instances will start fetching the new MTU as the DHCP T1 timer
    expires. As explained before, instances not obeying the DHCP T1
    parameter will need to be restarted, and instances with static IP
    assignment will need to be manually updated.
    """
    if len(sys.argv) < 3:
        print_usage()
        sys.exit(1)

    retval = 1
    if sys.argv[1] == "update" and sys.argv[2] == "mtu":
        if update_network_mtu():
            retval = 0
    elif sys.argv[1] == "verify" and sys.argv[2] == "mtu":
        if verify_network_mtu():
            retval = 0
    else:
        print_usage()

    sys.exit(retval)


if __name__ == "__main__":
    main()

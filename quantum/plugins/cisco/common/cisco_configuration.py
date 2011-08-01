# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
#
# @author: Sumit Naiksatam, Cisco Systems, Inc.
# @author: Edgar Magana, Cisco Systems, Inc.
#
from quantum.common import flags

# Note: All configuration values defined here are strings
FLAGS = flags.FLAGS
#
# TODO (Sumit): The following are defaults, but we also need to add to config
# file
#
flags.DEFINE_string('ucsm_ip_address', "172.20.231.27", 'IP address of \
                    UCSM')
flags.DEFINE_string('nexus_ip_address', "172.20.231.61", 'IP address of \
                     Nexus Switch')
flags.DEFINE_string('nexus_port', "3/23", 'Port number of the Interface  \
                     connected from the Nexus Switch to UCSM 6120')
flags.DEFINE_string('db_server_ip', "127.0.0.1", 'IP address of nova DB \
                    server')
flags.DEFINE_string('nova_host_name', "openstack-0203", 'nova cloud \
                    controller hostname')

flags.DEFINE_string('db_name', "nova", 'DB name')
flags.DEFINE_string('vlan_name_prefix', "q-", 'Prefix of the name given \
                    to the VLAN')
flags.DEFINE_string('profile_name_prefix', "q-", 'Prefix of the name \
                    given to the port profile')
flags.DEFINE_string('vlan_start', "100", 'This is the start value of the \
                    allowable VLANs')
flags.DEFINE_string('vlan_end', "3000", 'This is the end value of the \
                    allowable VLANs')
flags.DEFINE_string('default_vlan_name', "default", 'This is the name of \
                    the VLAN which will be associated with the port profile \
                    when it is created, by default the VMs will be on this \
                    VLAN, until attach is called')
flags.DEFINE_string('default_vlan_id', "1", 'This is the name of the VLAN \
                    which will be associated with the port profile when it \
                    is created, by default the VMs will be on this VLAN, \
                    until attach is called')
flags.DEFINE_string('nova_proj_name', "demo", 'project created in nova')
#
# TODO (Sumit): SAVBU to provide the accurate number below
#
flags.DEFINE_string('max_ucsm_port_profiles', "1024", 'This is the maximum \
                    number port profiles that can be handled by one UCSM.')
flags.DEFINE_string('max_port_profiles', "65568", 'This is the maximum \
                    number port profiles that can be handled by Cisco \
                    plugin. Currently this is just an arbitrary number.')
flags.DEFINE_string('max_networks', "65568", 'This is the maximum number \
                    of networks that can be handled by Cisco plugin. \
                    Currently this is just an arbitrary number.')

flags.DEFINE_string('get_next_vif',
                    "/root/sumit/quantum/quantum/plugins/cisco/get-vif.sh",
                    'This is the location of the script to get the next \
                    next available dynamic nic')

# Inventory items
UCSM_IP_ADDRESS = FLAGS.ucsm_ip_address
NEXUS_IP_ADDRESS = FLAGS.nexus_ip_address
NEXUS_PORT = FLAGS.nexus_port
DB_SERVER_IP = FLAGS.db_server_ip
NOVA_HOST_NAME = FLAGS.nova_host_name

# General configuration items
DB_NAME = FLAGS.db_name
VLAN_NAME_PREFIX = FLAGS.vlan_name_prefix
PROFILE_NAME_PREFIX = FLAGS.profile_name_prefix
VLAN_START = FLAGS.vlan_start
VLAN_END = FLAGS.vlan_end
DEFAULT_VLAN_NAME = FLAGS.default_vlan_name
DEFAULT_VLAN_ID = FLAGS.default_vlan_id
NOVA_PROJ_NAME = FLAGS.nova_proj_name
MAX_UCSM_PORT_PROFILES = FLAGS.max_ucsm_port_profiles
MAX_PORT_PROFILES = FLAGS.max_port_profiles
MAX_NETWORKS = FLAGS.max_networks

GET_NEXT_VIF_SCRIPT = FLAGS.get_next_vif

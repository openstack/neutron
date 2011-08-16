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
#

import os

from quantum.plugins.cisco.common import cisco_configparser as confp

CONF_FILE = "../conf/ucs.ini"

cp = confp.CiscoConfigParser(os.path.dirname(os.path.realpath(__file__)) \
                             + "/" + CONF_FILE)

section = cp['UCSM']
UCSM_IP_ADDRESS = section['ip_address']
DEFAULT_VLAN_NAME = section['default_vlan_name']
DEFAULT_VLAN_ID = section['default_vlan_id']
MAX_UCSM_PORT_PROFILES = section['max_ucsm_port_profiles']
PROFILE_NAME_PREFIX = section['profile_name_prefix']

section = cp['DRIVER']
UCSM_DRIVER = section['name']

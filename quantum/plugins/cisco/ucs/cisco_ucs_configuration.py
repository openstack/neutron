"""
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
"""

import os
from quantum.common.config import find_config_file
from quantum.plugins.cisco.common import cisco_configparser as confp

CP = confp.CiscoConfigParser(find_config_file({'plugin': 'cisco'}, [],
                             'ucs.ini'))

SECTION = CP['UCSM']
UCSM_IP_ADDRESS = SECTION['ip_address']
DEFAULT_VLAN_NAME = SECTION['default_vlan_name']
DEFAULT_VLAN_ID = SECTION['default_vlan_id']
MAX_UCSM_PORT_PROFILES = SECTION['max_ucsm_port_profiles']
PROFILE_NAME_PREFIX = SECTION['profile_name_prefix']

SECTION = CP['DRIVER']
UCSM_DRIVER = SECTION['name']

CP = confp.CiscoConfigParser(find_config_file({'plugin': 'cisco'}, [],
                             'ucs_inventory.ini'))

INVENTORY = CP.walk(CP.dummy)

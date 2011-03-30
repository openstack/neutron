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
"""
Configuration consolidation for the Nexus Driver
This module will export the configuration parameters
from the nexus.ini file
"""
import os

from quantum.common.config import find_config_file
from quantum.plugins.cisco.common import cisco_configparser as confp

CP = confp.CiscoConfigParser(find_config_file({'plugin': 'cisco'}, None,
                             "nexus.ini"))

SECTION = CP['SWITCH']
NEXUS_IP_ADDRESS = SECTION['nexus_ip_address']
NEXUS_FIRST_PORT = SECTION['nexus_first_port']
NEXUS_SECOND_PORT = SECTION['nexus_second_port']
NEXUS_SSH_PORT = SECTION['nexus_ssh_port']

SECTION = CP['DRIVER']
NEXUS_DRIVER = SECTION['name']

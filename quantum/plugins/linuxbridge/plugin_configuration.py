"""
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Cisco Systems, Inc.  All rights reserved.
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
# @author: Rohit Agarwalla, Cisco Systems, Inc.
"""

import os

from quantum.common.config import find_config_file
from quantum.plugins.linuxbridge.common import configparser as confp


CONF_FILE = find_config_file({'plugin': 'linuxbridge'}, None,
                             "linuxbridge_conf.ini")
CONF_PARSER_OBJ = confp.ConfigParser(CONF_FILE)


"""
Reading the conf for the linuxbridge_plugin
"""
SECTION_CONF = CONF_PARSER_OBJ['VLANS']
VLAN_START = SECTION_CONF['vlan_start']
VLAN_END = SECTION_CONF['vlan_end']


SECTION_CONF = CONF_PARSER_OBJ['DATABASE']
DB_SQL_CONNECTION = SECTION_CONF['sql_connection']
if 'reconnect_interval' in SECTION_CONF:
    DB_RECONNECT_INTERVAL = int(SECTION_CONF['reconnect_interval'])
else:
    DB_RECONNECT_INTERVAL = 2

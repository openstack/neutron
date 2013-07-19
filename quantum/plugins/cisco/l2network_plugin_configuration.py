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
# @author: Rohit Agarwalla, Cisco Systems, Inc.

from quantum.common.utils import find_config_file
from quantum.plugins.cisco.common import cisco_configparser as confp


CONF_FILE = find_config_file({'plugin': 'cisco'}, "l2network_plugin.ini")
CONF_PARSER_OBJ = confp.CiscoConfigParser(CONF_FILE)
# Read the conf for the l2network_plugin
SECTION_CONF = CONF_PARSER_OBJ['VLANS']
VLAN_NAME_PREFIX = SECTION_CONF['vlan_name_prefix']
SECTION_CONF = CONF_PARSER_OBJ['MODEL']
MODEL_CLASS = SECTION_CONF['model_class']

CONF_FILE = find_config_file({'plugin': 'cisco'}, "cisco_plugins.ini")
CONF_PARSER_OBJ = confp.CiscoConfigParser(CONF_FILE)
# Read the config for the device plugins
PLUGINS = CONF_PARSER_OBJ.walk(CONF_PARSER_OBJ.dummy)

CONF_FILE = find_config_file({'plugin': 'cisco'}, "db_conn.ini")
CONF_PARSER_OBJ = confp.CiscoConfigParser(CONF_FILE)
# Read DB config for the Quantum DB
SECTION_CONF = CONF_PARSER_OBJ['DATABASE']
DB_NAME = SECTION_CONF['name']
DB_USER = SECTION_CONF['user']
DB_PASS = SECTION_CONF['pass']
DB_HOST = SECTION_CONF['host']

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

CONF_FILE = "../conf/nova.ini"

cp = confp.CiscoConfigParser(os.path.dirname(os.path.realpath(__file__)) \
                             + "/" + CONF_FILE)

section = cp['NOVA']
DB_SERVER_IP = section['db_server_ip']
DB_NAME = section['db_name']
DB_USERNAME = section['db_username']
DB_PASSWORD = section['db_password']
NOVA_HOST_NAME = section['nova_host_name']
NOVA_PROJ_NAME = section['nova_proj_name']

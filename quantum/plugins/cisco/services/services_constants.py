# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 OpenStack LLC
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
#    @author: Edgar Magana, Cisco Systems
#
"""
Services Constants for the Services insertion Library
"""


FORMAT = 'json'
ACTION_PREFIX_EXT = '/v1.0'
ACTION_PREFIX_CSCO = ACTION_PREFIX_EXT + \
        '/extensions/csco/tenants/{tenant_id}'
NETWORK = 'network'
ID = 'id'
PORTS = 'ports'
PORT = 'port'
NAME = 'name'
ATTACHMENT = 'attachment'
CREATE_VM_CMD = '/usr/bin/euca-run-instances'
DELETE_VM_CMD = '/usr/bin/euca-terminate-instances'
DESCRIBE_VM_CMD = '/usr/bin/euca-describe-instances'

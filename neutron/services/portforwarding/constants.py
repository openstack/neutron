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

# TODO(flaviof): This file is a place holder. Everything here should move to
#                neutron-lib someday.

# String literals representing core resources.
# TODO(flaviof): move to neutron_lib/callbacks/resources.py
from ovsdbapp import constants as const

PORT_FORWARDING = 'port_forwarding'
PORT_FORWARDING_PLUGIN = 'port_forwarding_plugin'
PORT_FORWARDING_PREFIX = 'pf-floatingip'
LB_PROTOCOL_MAP = {'udp': const.PROTO_UDP, 'tcp': const.PROTO_TCP}

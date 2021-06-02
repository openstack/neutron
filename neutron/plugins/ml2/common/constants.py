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

from neutron_lib import constants

DEFAULT_DEVICE_OWNER = ''

# TODO(liuyulong): move to neutron-lib or common constants
NO_PBLOCKS_TYPES = [
    DEFAULT_DEVICE_OWNER,
    constants.DEVICE_OWNER_DVR_INTERFACE,
    constants.DEVICE_OWNER_HA_REPLICATED_INT,
    constants.DEVICE_OWNER_ROUTER_INTF,
    constants.DEVICE_OWNER_ROUTER_GW,
    constants.DEVICE_OWNER_ROUTER_SNAT,
    constants.DEVICE_OWNER_DHCP,
    constants.DEVICE_OWNER_AGENT_GW,
    constants.DEVICE_OWNER_ROUTER_HA_INTF,
    constants.DEVICE_OWNER_FLOATINGIP,
]

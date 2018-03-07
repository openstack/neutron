# Copyright 2012 OpenStack Foundation.
# All Rights Reserved.
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

from neutron_lib.plugins import constants as p_const


# Maps extension alias to service type that
# can be implemented by the core plugin.
EXT_TO_SERVICE_MAPPING = {
    'lbaas': p_const.LOADBALANCER,
    'lbaasv2': p_const.LOADBALANCERV2,
    'fwaas': p_const.FIREWALL,
    'vpnaas': p_const.VPN,
    'metering': p_const.METERING,
    'router': p_const.L3,
    'qos': p_const.QOS,
}

# Maps default service plugins entry points to their extension aliases
DEFAULT_SERVICE_PLUGINS = {
    'auto_allocate': 'auto-allocated-topology',
    'tag': 'tag',
    'timestamp': 'timestamp',
    'network_ip_availability': 'network-ip-availability',
    'flavors': 'flavors',
    'revisions': 'revisions',
}

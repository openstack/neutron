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

from neutron.api.v2 import attributes
from neutron.db import common_db_mixin
from neutron.extensions import availability_zone as az_ext
from neutron.extensions import network_availability_zone as net_az


class NetworkAvailabilityZoneMixin(net_az.NetworkAvailabilityZonePluginBase):
    """Mixin class to enable network's availability zone attributes."""

    def _extend_availability_zone(self, net_res, net_db):
        net_res[az_ext.AZ_HINTS] = az_ext.convert_az_string_to_list(
            net_db[az_ext.AZ_HINTS])
        net_res[az_ext.AVAILABILITY_ZONES] = (
            self.get_network_availability_zones(net_db))

    common_db_mixin.CommonDbMixin.register_dict_extend_funcs(
        attributes.NETWORKS, ['_extend_availability_zone'])

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

from neutron_lib.api.definitions import availability_zone as az_def
from neutron_lib.api.definitions import network as net_def
from neutron_lib.api.validators import availability_zone as az_validator
from neutron_lib.plugins import directory

from neutron.db import _resource_extend as resource_extend
from neutron.extensions import network_availability_zone as net_az


@resource_extend.has_resource_extenders
class NetworkAvailabilityZoneMixin(net_az.NetworkAvailabilityZonePluginBase):
    """Mixin class to enable network's availability zone attributes."""

    @staticmethod
    @resource_extend.extends([net_def.COLLECTION_NAME])
    def _extend_availability_zone(net_res, net_db):
        net_res[az_def.AZ_HINTS] = az_validator.convert_az_string_to_list(
            net_db[az_def.AZ_HINTS])
        plugin = directory.get_plugin()
        net_res[az_def.COLLECTION_NAME] = (
            plugin.get_network_availability_zones(net_db))

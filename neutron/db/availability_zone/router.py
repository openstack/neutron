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
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory

from neutron.common import utils
from neutron.db import _resource_extend as resource_extend
from neutron.db import l3_attrs_db


@resource_extend.has_resource_extenders
@registry.has_registry_receivers
class RouterAvailabilityZoneMixin(l3_attrs_db.ExtraAttributesMixin):
    """Mixin class to enable router's availability zone attributes."""

    @staticmethod
    @resource_extend.extends([l3_apidef.ROUTERS])
    def _add_az_to_response(router_res, router_db):
        l3_plugin = directory.get_plugin(constants.L3)
        if not utils.is_extension_supported(l3_plugin,
                                            'router_availability_zone'):
            return
        router_res['availability_zones'] = (
            l3_plugin.get_router_availability_zones(router_db))

    @registry.receives(resources.ROUTER, [events.PRECOMMIT_CREATE])
    def _process_az_request(self, resource, event, trigger, context,
                            router, router_db, **kwargs):
        if az_def.AZ_HINTS in router:
            self.validate_availability_zones(context, 'router',
                                             router[az_def.AZ_HINTS])
            self.set_extra_attr_value(context, router_db, az_def.AZ_HINTS,
                                      router[az_def.AZ_HINTS])

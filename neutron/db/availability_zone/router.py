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

from neutron.common import utils
from neutron.db import l3_attrs_db
from neutron.extensions import availability_zone as az_ext


class RouterAvailabilityZoneMixin(l3_attrs_db.ExtraAttributesMixin):
    """Mixin class to enable router's availability zone attributes."""

    extra_attributes = [{'name': az_ext.AZ_HINTS, 'default': "[]"}]

    def _extend_extra_router_dict(self, router_res, router_db):
        super(RouterAvailabilityZoneMixin, self)._extend_extra_router_dict(
            router_res, router_db)
        if not utils.is_extension_supported(self, 'router_availability_zone'):
            return
        router_res[az_ext.AZ_HINTS] = az_ext.convert_az_string_to_list(
            router_res[az_ext.AZ_HINTS])
        router_res['availability_zones'] = (
            self.get_router_availability_zones(router_db))

    def _process_extra_attr_router_create(
        self, context, router_db, router_req):
        if az_ext.AZ_HINTS in router_req:
            self.validate_availability_zones(context, 'router',
                                             router_req[az_ext.AZ_HINTS])
            router_req[az_ext.AZ_HINTS] = az_ext.convert_az_list_to_string(
                router_req[az_ext.AZ_HINTS])
        super(RouterAvailabilityZoneMixin,
              self)._process_extra_attr_router_create(context, router_db,
                                                      router_req)

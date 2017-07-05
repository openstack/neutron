# Copyright 2016 Hewlett Packard Enterprise Development Company, LP
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

# TODO(ihrachys): consider renaming the module since now it does not contain
# any models at all

from neutron_lib.api.definitions import subnet as subnet_def

from neutron.db import _resource_extend as resource_extend


@resource_extend.has_resource_extenders
class SubnetServiceTypeMixin(object):
    """Mixin class to extend subnet with service type attribute"""

    @staticmethod
    @resource_extend.extends([subnet_def.COLLECTION_NAME])
    def _extend_subnet_service_types(subnet_res, subnet_db):
        subnet_res['service_types'] = [service_type['service_type'] for
                                       service_type in
                                       subnet_db.service_types]

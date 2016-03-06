# All rights reserved.
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
from neutron.extensions import l3
from neutron.extensions import securitygroup


class StandardAttrDescriptionMixin(object):
    supported_extension_aliases = ['standard-attr-description']

    def _extend_standard_attr_description(self, res, db_object):
        if not hasattr(db_object, 'description'):
            return
        res['description'] = db_object.description

    for resource in [attributes.NETWORKS, attributes.PORTS,
                     attributes.SUBNETS, attributes.SUBNETPOOLS,
                     securitygroup.SECURITYGROUPS,
                     securitygroup.SECURITYGROUPRULES,
                     l3.ROUTERS, l3.FLOATINGIPS]:
        common_db_mixin.CommonDbMixin.register_dict_extend_funcs(
            resource, ['_extend_standard_attr_description'])

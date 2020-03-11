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

from neutron_lib import constants as n_const
from oslo_versionedobjects import fields as obj_fields

from neutron.db.models.plugins.ml2 import flatallocation
from neutron.objects import base


@base.NeutronObjectRegistry.register
class FlatAllocation(base.NeutronDbObject):
    # Version 1.0: Initial Version
    VERSION = '1.0'

    db_model = flatallocation.FlatAllocation

    fields = {
        'physical_network': obj_fields.StringField()
    }

    primary_keys = ['physical_network']

    network_type = n_const.TYPE_FLAT

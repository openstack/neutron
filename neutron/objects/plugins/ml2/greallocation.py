# Copyright (c) 2016 Intel Corporation.
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

from neutron_lib import constants as n_const
from oslo_versionedobjects import fields as obj_fields

from neutron.db.models.plugins.ml2 import gre_allocation_endpoints as gre_model
from neutron.objects import base
from neutron.objects.plugins.ml2 import base as ml2_base


@base.NeutronObjectRegistry.register
class GreAllocation(base.NeutronDbObject, ml2_base.SegmentAllocation):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = gre_model.GreAllocation

    primary_keys = ['gre_id']

    fields = {
        'gre_id': obj_fields.IntegerField(),
        'allocated': obj_fields.BooleanField(default=False)
    }

    network_type = n_const.TYPE_GRE

    @classmethod
    def get_segmentation_id(cls):
        return cls.db_model.get_segmentation_id()


@base.NeutronObjectRegistry.register
class GreEndpoint(ml2_base.EndpointBase):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = gre_model.GreEndpoints

    fields = {
        'ip_address': obj_fields.IPAddressField(),
        'host': obj_fields.StringField(nullable=True)
    }

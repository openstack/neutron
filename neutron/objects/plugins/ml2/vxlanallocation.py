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
from neutron_lib.objects import common_types
from oslo_versionedobjects import fields as obj_fields

from neutron.db.models.plugins.ml2 import vxlanallocation as vxlan_model
from neutron.objects import base
from neutron.objects.plugins.ml2 import base as ml2_base


@base.NeutronObjectRegistry.register
class VxlanAllocation(base.NeutronDbObject, ml2_base.SegmentAllocation):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = vxlan_model.VxlanAllocation

    primary_keys = ['vxlan_vni']

    fields = {
        'vxlan_vni': obj_fields.IntegerField(),
        'allocated': obj_fields.BooleanField(default=False),
    }

    network_type = n_const.TYPE_VXLAN

    @classmethod
    def get_segmentation_id(cls):
        return cls.db_model.get_segmentation_id()


@base.NeutronObjectRegistry.register
class VxlanEndpoint(ml2_base.EndpointBase):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = vxlan_model.VxlanEndpoints

    fields = {
        'ip_address': obj_fields.IPAddressField(),
        'udp_port': common_types.PortRangeField(),
        'host': obj_fields.StringField(nullable=True),
    }

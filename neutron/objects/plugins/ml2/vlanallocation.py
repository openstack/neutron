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

from neutron.db.models.plugins.ml2 import vlanallocation as vlan_alloc_model
from neutron.objects import base
from neutron.objects import common_types
from neutron.objects.plugins.ml2 import base as ml2_base


@base.NeutronObjectRegistry.register
class VlanAllocation(base.NeutronDbObject, ml2_base.SegmentAllocation):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = vlan_alloc_model.VlanAllocation

    fields = {
        'physical_network': obj_fields.StringField(),
        'vlan_id': common_types.VlanIdRangeField(),
        'allocated': obj_fields.BooleanField(),
    }

    primary_keys = ['physical_network', 'vlan_id']

    network_type = n_const.TYPE_VLAN

    @staticmethod
    def get_physical_networks(context):
        query = context.session.query(VlanAllocation.db_model.physical_network)
        query = query.group_by(VlanAllocation.db_model.physical_network)
        physnets = query.all()
        return {physnet.physical_network for physnet in physnets}

    @staticmethod
    def delete_physical_networks(context, physical_networks):
        column = VlanAllocation.db_model.physical_network
        context.session.query(VlanAllocation.db_model).filter(
            column.in_(physical_networks)).delete(synchronize_session=False)

    @staticmethod
    def bulk_create(ctx, physical_network, vlan_ids):
        ctx.session.bulk_insert_mappings(
            vlan_alloc_model.VlanAllocation,
            [{'physical_network': physical_network,
              'allocated': False,
              'vlan_id': vlan_id} for vlan_id in vlan_ids])

    @classmethod
    def update_primary_keys(cls, _dict, segmentation_id=None,
                            physical_network=None):
        _dict['physical_network'] = physical_network
        _dict['vlan_id'] = segmentation_id

    @classmethod
    def get_segmentation_id(cls):
        return cls.db_model.get_segmentation_id()

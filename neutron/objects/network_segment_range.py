# Copyright (c) 2019 Intel Corporation.
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

from neutron_lib.api.definitions import network_segment_range as nsr_def
from neutron_lib import constants
from neutron_lib.db import resource_extend
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as n_exc
from neutron_lib.objects import common_types
from oslo_utils import uuidutils
from oslo_versionedobjects import fields as obj_fields
from sqlalchemy import and_
from sqlalchemy import sql

from neutron._i18n import _
from neutron.common import utils as n_utils
from neutron.db.models import network_segment_range as range_model
from neutron.db.models import segment as segments_model
from neutron.db import models_v2
from neutron.objects import base


SEGMENT_RANGE_TYPES = {
    constants.TYPE_VLAN,
    constants.TYPE_VXLAN,
    constants.TYPE_GRE,
    constants.TYPE_GENEVE,
}


@base.NeutronObjectRegistry.register
class NetworkSegmentRange(base.NeutronDbObject):
    # Version 1.0: Initial version
    # Version 1.1: Add unique constraint and make 'physical_network' not
    #              nullable
    VERSION = '1.1'

    db_model = range_model.NetworkSegmentRange

    primary_keys = ['id']

    fields = {
        'id': common_types.UUIDField(),
        'name': obj_fields.StringField(nullable=True),
        'default': obj_fields.BooleanField(nullable=False),
        'shared': obj_fields.BooleanField(nullable=False),
        'project_id': obj_fields.StringField(nullable=True),
        'network_type': common_types.NetworkSegmentRangeNetworkTypeEnumField(
            nullable=False),
        'physical_network': obj_fields.StringField(nullable=False),
        'minimum': obj_fields.IntegerField(nullable=True),
        'maximum': obj_fields.IntegerField(nullable=True)
    }

    def to_dict(self, fields=None):
        _dict = super().to_dict()
        _dict.update({'available': self._get_available_allocation()})
        _dict.update({'used': self._get_used_allocation_mapping()})
        _dict = db_utils.resource_fields(_dict, fields)
        # TODO(ralonsoh): remove once bp/keystone-v3 migration finishes.
        _dict.pop('tenant_id', None)
        resource_extend.apply_funcs(nsr_def.COLLECTION_NAME, _dict,
                                    self.db_obj)
        return _dict

    def _check_shared_project_id(self, action):
        if self.shared is False and not self.project_id:
            raise n_exc.ObjectActionError(
                action=action,
                reason='if NetworkSegmentRange is not shared, it must have a '
                       'project_id')

    def create(self):
        self._check_shared_project_id('create')
        super().create()

    def update(self):
        self._check_shared_project_id('update')
        super().update()

    def _get_available_allocation(self):
        """Return segmentation IDs in [minimum, maximum] not yet used."""
        all_ids = set(range(self.minimum, self.maximum + 1))
        used = set(self._get_used_allocation_mapping().keys())
        return sorted(all_ids - used)

    def _get_used_allocation_mapping(self):
        with self.db_context_reader(self.obj_context):
            query = self.obj_context.session.query(
                segments_model.NetworkSegment.segmentation_id,
                models_v2.Network.project_id)
            alloc_used = (query.filter(and_(
                segments_model.NetworkSegment.network_type ==
                self.network_type,
                segments_model.NetworkSegment.physical_network ==
                self.physical_network,
                segments_model.NetworkSegment.segmentation_id >= self.minimum,
                segments_model.NetworkSegment.segmentation_id <= self.maximum))
                          .filter(segments_model.NetworkSegment.network_id ==
                                  models_v2.Network.id)).all()
        return dict(alloc_used)

    @classmethod
    def delete_expired_default_network_segment_ranges(
            cls, context, network_type, start_time):
        if network_type not in SEGMENT_RANGE_TYPES:
            msg = (_("network_type '%s' unknown for getting allocation "
                     "information") % network_type)
            raise n_exc.InvalidInput(error_message=msg)
        created_at = n_utils.ts_to_datetime(start_time)
        with cls.db_context_writer(context):
            nsr_ids = context.session.query(cls.db_model.id).filter(
                cls.db_model.default == sql.expression.true(),
                cls.db_model.network_type == network_type,
                cls.db_model.created_at != created_at).all()
            nsr_ids = [nsr_id[0] for nsr_id in nsr_ids]
            if nsr_ids:
                NetworkSegmentRange.delete_objects(context, id=nsr_ids)

    @classmethod
    def new_default(cls, context, network_type, physical_network,
                    minimum, maximum, start_time):
        physical_network = physical_network or ''
        if network_type not in SEGMENT_RANGE_TYPES:
            msg = (_("network_type '%s' unknown for getting allocation "
                     "information") % network_type)
            raise n_exc.InvalidInput(error_message=msg)
        created_at = n_utils.ts_to_datetime(start_time)
        with cls.db_context_writer(context):
            if context.session.query(cls.db_model).filter(
                cls.db_model.default == sql.expression.true(),
                cls.db_model.shared == sql.expression.true(),
                cls.db_model.network_type == network_type,
                cls.db_model.physical_network == physical_network,
                cls.db_model.minimum == minimum,
                cls.db_model.maximum == maximum,
                cls.db_model.created_at == created_at,
            ).first():
                return

        cls(context, id=uuidutils.generate_uuid(), default=True, shared=True,
            network_type=network_type, physical_network=physical_network,
            minimum=minimum, maximum=maximum, created_at=created_at).create()

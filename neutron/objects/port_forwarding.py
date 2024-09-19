# Copyright (c) 2018 OpenStack Foundation
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

import itertools

import netaddr
from neutron_lib.db import api as db_api
from neutron_lib.objects import common_types

from neutron.db.models import l3
from neutron.db.models import port_forwarding as models
from neutron.objects import base
from neutron_lib import constants as lib_const
from oslo_utils import versionutils
from oslo_versionedobjects import fields as obj_fields

FIELDS_NOT_SUPPORT_FILTER = ['internal_ip_address', 'internal_port']


@base.NeutronObjectRegistry.register
class PortForwarding(base.NeutronDbObject):
    # Version 1.0: Initial version
    # Version 1.1: Change unique constraint
    # Version 1.2: Add "description" field
    # Version 1.3: Add "external_port_range" and "internal_port_range" fields
    VERSION = '1.3'

    db_model = models.PortForwarding

    primary_keys = ['id']
    foreign_keys = {'FloatingIP': {'floatingip_id': 'id'},
                    'Port': {'internal_port_id': 'id'}}

    fields_need_translation = {
        'internal_port_id': 'internal_neutron_port_id'
    }

    fields = {
        'id': common_types.UUIDField(),
        'floatingip_id': common_types.UUIDField(nullable=False),
        'external_port': common_types.PortRangeField(nullable=True),
        'external_port_range': common_types.PortRangesField(nullable=True),
        'protocol': common_types.IpProtocolEnumField(nullable=False),
        'internal_port_id': common_types.UUIDField(nullable=False),
        'internal_ip_address': obj_fields.IPV4AddressField(),
        'internal_port': common_types.PortRangeField(nullable=True),
        'internal_port_range': common_types.PortRangesField(nullable=True),
        'floating_ip_address': obj_fields.IPV4AddressField(),
        'router_id': common_types.UUIDField(),
        'description': obj_fields.StringField()
    }

    comparision_ignored_fields = ['revision_number', 'updated_at',
                                  'created_at']

    synthetic_fields = ['floating_ip_address', 'router_id']
    fields_no_update = ['id', 'floatingip_id']

    def __eq__(self, other):
        for attr in self.fields:
            # Some fields are inherited from standards attributes and are
            # irrelevant while comparing two PortForwarding.
            if attr in self.comparision_ignored_fields:
                continue

            if getattr(self, attr) != getattr(other, attr):
                return False
        return True

    def _new_instance(self, **kwargs):
        fields_parameters = {f: getattr(self, f)
                             for f in self.fields if hasattr(self, f)}
        sanitized_kwargs = {k: kwargs[k]
                            for k in kwargs if k in self.fields}
        fields_parameters.update(sanitized_kwargs)
        return PortForwarding(**fields_parameters)

    def unroll_port_ranges(self):
        extrn_port_range = self.external_port_range
        intrn_port_range = self.internal_port_range
        if not extrn_port_range:
            return [self]

        if ':' not in extrn_port_range:
            return [self._new_instance(
                external_port=int(extrn_port_range),
                internal_port=self.internal_port or int(intrn_port_range),
                external_port_range=None,
                internal_port_range=None
            )]

        if ":" not in intrn_port_range:
            intrn_port_range = "{ipr}:{ipr}".format(ipr=intrn_port_range)

        extrn_min, extrn_max = map(int, extrn_port_range.split(':'))
        intrn_min, intrn_max = map(int, intrn_port_range.split(':'))
        external_ports = list(range(extrn_min, extrn_max + 1))
        internal_ports = list(range(intrn_min, intrn_max + 1))
        intrn_multiplier = 1 if intrn_min != intrn_max else 0
        portforwardings = []
        for i, external_port in enumerate(external_ports):
            internal_port = internal_ports[i * intrn_multiplier]
            portforwardings.append(
                self._new_instance(
                    external_port=external_port,
                    internal_port=internal_port,
                    external_port_range=None,
                    internal_port_range=None
                ),
            )
        return portforwardings

    def obj_load_attr(self, attrname):
        if attrname in ['floating_ip_address', 'router_id']:
            return self._load_attr_from_fip(attrname)
        super().obj_load_attr(attrname)

    def _load_attr_from_fip(self, attrname):
        value = getattr(self.db_obj.floating_ip, attrname)
        setattr(self, attrname, value)
        self.obj_reset_changes([attrname])

    def from_db_object(self, db_obj):
        super().from_db_object(db_obj)
        self._load_attr_from_fip(attrname='router_id')
        self._load_attr_from_fip(attrname='floating_ip_address')

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 2):
            primitive.pop('description', None)
        if _target_version < (1, 3):
            primitive['internal_port'] = int(
                str(primitive.pop(
                    'internal_port_range',
                    str(primitive.get('internal_port',
                                      '')))).split(':', maxsplit=1)[0])
            primitive['external_port'] = int(
                str(primitive.pop(
                    'external_port_range',
                    str(primitive.get('external_port',
                                      '')))).split(':', maxsplit=1)[0])

    @staticmethod
    def _modify_single_ports_to_db(result):
        internal_port = result.pop('internal_port', None)
        external_port = result.pop('external_port', None)
        if internal_port:
            result['internal_port_start'] = internal_port
            result['internal_port_end'] = internal_port

        if external_port:
            result['external_port_start'] = external_port
            result['external_port_end'] = external_port

    @staticmethod
    def _modify_ports_range_to_db(result):
        internal_port_range = result.pop('internal_port_range', None)
        external_port_range = result.pop('external_port_range', None)
        if internal_port_range:
            if isinstance(internal_port_range, list):
                internal_port_range = internal_port_range[0]
            if isinstance(internal_port_range,
                          int) or internal_port_range.isnumeric():
                start = end = str(internal_port_range)

            else:
                start, end = internal_port_range.split(':')

            result['internal_port_start'] = start
            result['internal_port_end'] = end

        if external_port_range:
            if isinstance(external_port_range, list):
                external_port_range = external_port_range[0]
            if isinstance(external_port_range,
                          int) or external_port_range.isnumeric():
                start = end = str(external_port_range)

            else:
                start, end = external_port_range.split(':')

            result['external_port_start'] = start
            result['external_port_end'] = end

    @staticmethod
    def _modify_ports_range_from_db(result,
                                    internal_port_start=None,
                                    internal_port_end=None,
                                    external_port_start=None,
                                    external_port_end=None):

        if not internal_port_start or not external_port_start:
            return

        result['external_port_range'] = '{}:{}'.format(external_port_start,
                                                       external_port_end)
        result['internal_port_range'] = '{}:{}'.format(internal_port_start,
                                                       internal_port_end)

    @staticmethod
    def _modify_single_ports_from_db(result,
                                     internal_port_start=None,
                                     internal_port_end=None,
                                     external_port_start=None,
                                     external_port_end=None):

        if not internal_port_start or not external_port_start:
            return
        if internal_port_start == internal_port_end:
            result['internal_port'] = int(internal_port_start)

        if external_port_start == external_port_end:
            result['external_port'] = int(external_port_start)

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        result = super().modify_fields_from_db(db_obj)
        if 'internal_ip_address' in result:
            result['internal_ip_address'] = netaddr.IPAddress(
                result['internal_ip_address'], version=lib_const.IP_VERSION_4)

        external_port_start = db_obj.get('external_port_start')
        external_port_end = db_obj.get('external_port_end')
        internal_port_start = db_obj.get('internal_port_start')
        internal_port_end = db_obj.get('internal_port_end')

        cls._modify_single_ports_from_db(
            result,
            internal_port_start=internal_port_start,
            external_port_start=external_port_start,
            internal_port_end=internal_port_end,
            external_port_end=external_port_end)
        cls._modify_ports_range_from_db(
            result,
            internal_port_start=internal_port_start,
            external_port_start=external_port_start,
            internal_port_end=internal_port_end,
            external_port_end=external_port_end)
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super().modify_fields_to_db(fields)
        cls._modify_ports_range_to_db(result)
        cls._modify_single_ports_to_db(result)
        if 'internal_ip_address' in result:
            if isinstance(result['internal_ip_address'], list):
                result['internal_ip_address'] = list(
                    map(str, result['internal_ip_address']))
            else:
                result['internal_ip_address'] = str(
                    result['internal_ip_address'])

        return result

    @classmethod
    @db_api.CONTEXT_READER
    def get_port_forwarding_obj_by_routers(cls, context, router_ids):
        query = context.session.query(cls.db_model, l3.FloatingIP)
        query = query.join(l3.FloatingIP,
                           cls.db_model.floatingip_id == l3.FloatingIP.id)
        query = query.filter(l3.FloatingIP.router_id.in_(router_ids))

        return cls._unique_port_forwarding(query)

    @staticmethod
    def _unique_port_forwarding(query):

        def _row_one(row):
            return row[1]

        q = query.order_by(l3.FloatingIP.router_id)
        group_iterator = itertools.groupby(q, _row_one)

        result = []
        for key, value in group_iterator:
            result.extend([(row[1]['router_id'], row[1]['floating_ip_address'],
                            row[0]['id'], row[1]['id']) for row in value])
        return result

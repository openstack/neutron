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

from neutron.db.models import l3
from neutron.db.models import port_forwarding as models
from neutron.objects import base
from neutron.objects import common_types
from neutron.objects import router
from neutron_lib import constants as lib_const
from oslo_versionedobjects import fields as obj_fields

FIELDS_NOT_SUPPORT_FILTER = ['internal_ip_address', 'internal_port']


@base.NeutronObjectRegistry.register
class PortForwarding(base.NeutronDbObject):
    # Version 1.0: Initial version
    # Version 1.1: Change unique constraint
    VERSION = '1.1'

    db_model = models.PortForwarding

    primary_keys = ['id']
    foreign_keys = {'FloatingIP': {'floatingip_id': 'id'},
                    'Port': {'internal_port_id': 'id'}}

    # Notes: 'socket': 'socket' maybe odd here, but for current OVO and the
    # definition of PortForwarding obj, this obj doesn't define a field named
    # "socket", but the db model does, it will get the value to store into db.
    # And this obj defines some fields like "internal_ip_address" and
    # "internal_port" which will construct "socket" field. Also there is
    # a reason why it like this. Please see neutron/objects/base.py#n468
    # So if we don't set it into fields_need_translation, the OVO base will
    # default skip the field from db.
    fields_need_translation = {
        'socket': 'socket',
        'internal_port_id': 'internal_neutron_port_id'
    }

    fields = {
        'id': common_types.UUIDField(),
        'floatingip_id': common_types.UUIDField(nullable=False),
        'external_port': common_types.PortRangeField(nullable=False),
        'protocol': common_types.IpProtocolEnumField(nullable=False),
        'internal_port_id': common_types.UUIDField(nullable=False),
        'internal_ip_address': obj_fields.IPV4AddressField(),
        'internal_port': common_types.PortRangeField(nullable=False),
        'floating_ip_address': obj_fields.IPV4AddressField(),
        'router_id': common_types.UUIDField()
    }

    synthetic_fields = ['floating_ip_address', 'router_id']
    fields_no_update = {
        'id', 'floatingip_id'
    }

    def __eq__(self, other):
        for attr in self.fields:
            if getattr(self, attr) != getattr(other, attr):
                return False
        return True

    def obj_load_attr(self, attrname):
        if attrname in ['floating_ip_address', 'router_id']:
            return self._load_attr_from_fip(attrname)
        super(PortForwarding, self).obj_load_attr(attrname)

    def _load_attr_from_fip(self, attrname):
        # get all necessary info from fip obj
        fip_obj = router.FloatingIP.get_object(
            self.obj_context, id=self.floatingip_id)
        value = getattr(fip_obj, attrname)
        setattr(self, attrname, value)
        self.obj_reset_changes([attrname])

    def from_db_object(self, db_obj):
        super(PortForwarding, self).from_db_object(db_obj)
        self._load_attr_from_fip(attrname='router_id')
        self._load_attr_from_fip(attrname='floating_ip_address')

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        result = super(PortForwarding, cls).modify_fields_from_db(db_obj)
        if 'socket' in result:
            groups = result['socket'].split(":")
            result['internal_ip_address'] = netaddr.IPAddress(
                groups[0], version=lib_const.IP_VERSION_4)
            result['internal_port'] = int(groups[1])
            del result['socket']
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(PortForwarding, cls).modify_fields_to_db(fields)
        if 'internal_ip_address' in result and 'internal_port' in result:
            result['socket'] = str(
                result['internal_ip_address']) + ":" + str(
                result['internal_port'])
            del result['internal_ip_address']
            del result['internal_port']
        return result

    @classmethod
    def get_port_forwarding_obj_by_routers(cls, context, router_ids):
        query = context.session.query(cls.db_model, l3.FloatingIP)
        query = query.join(l3.FloatingIP,
                           cls.db_model.floatingip_id == l3.FloatingIP.id)
        query = query.filter(l3.FloatingIP.router_id.in_(router_ids))

        return cls._unique_port_forwarding_iterator(query)

    @classmethod
    def _unique_port_forwarding_iterator(cls, query):
        q = query.order_by(l3.FloatingIP.router_id)
        keyfunc = lambda row: row[1]
        group_iterator = itertools.groupby(q, keyfunc)

        for key, value in group_iterator:
            for row in value:
                yield (row[1]['router_id'], row[1]['floating_ip_address'],
                       row[0]['id'], row[1]['id'])

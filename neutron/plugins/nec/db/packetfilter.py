# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012-2013 NEC Corporation.  All rights reserved.
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
# @author: Ryota MIBU

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc as sa_exc

from neutron.api.v2 import attributes
from neutron.common import exceptions
from neutron.db import model_base
from neutron.db import models_v2
from neutron.openstack.common import uuidutils


PF_STATUS_ACTIVE = 'ACTIVE'
PF_STATUS_DOWN = 'DOWN'
PF_STATUS_ERROR = 'ERROR'


class PacketFilterNotFound(exceptions.NotFound):
    message = _("PacketFilter %(id)s could not be found")


class PacketFilter(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a packet filter."""
    name = sa.Column(sa.String(255))
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           nullable=False)
    priority = sa.Column(sa.Integer, nullable=False)
    action = sa.Column(sa.String(16), nullable=False)
    # condition
    in_port = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        nullable=True)
    src_mac = sa.Column(sa.String(32), nullable=False)
    dst_mac = sa.Column(sa.String(32), nullable=False)
    eth_type = sa.Column(sa.Integer, nullable=False)
    src_cidr = sa.Column(sa.String(64), nullable=False)
    dst_cidr = sa.Column(sa.String(64), nullable=False)
    protocol = sa.Column(sa.String(16), nullable=False)
    src_port = sa.Column(sa.Integer, nullable=False)
    dst_port = sa.Column(sa.Integer, nullable=False)
    # status
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    status = sa.Column(sa.String(16), nullable=False)

    network = orm.relationship(
        models_v2.Network,
        backref=orm.backref('packetfilters', lazy='joined', cascade='delete'),
        uselist=False)
    in_port_ref = orm.relationship(
        models_v2.Port,
        backref=orm.backref('packetfilters', lazy='joined', cascade='delete'),
        primaryjoin="Port.id==PacketFilter.in_port",
        uselist=False)


class PacketFilterDbMixin(object):

    def _make_packet_filter_dict(self, pf_entry, fields=None):
        res = {'id': pf_entry['id'],
               'name': pf_entry['name'],
               'tenant_id': pf_entry['tenant_id'],
               'network_id': pf_entry['network_id'],
               'action': pf_entry['action'],
               'priority': pf_entry['priority'],
               'in_port': pf_entry['in_port'],
               'src_mac': pf_entry['src_mac'],
               'dst_mac': pf_entry['dst_mac'],
               'eth_type': pf_entry['eth_type'],
               'src_cidr': pf_entry['src_cidr'],
               'dst_cidr': pf_entry['dst_cidr'],
               'protocol': pf_entry['protocol'],
               'src_port': pf_entry['src_port'],
               'dst_port': pf_entry['dst_port'],
               'admin_state_up': pf_entry['admin_state_up'],
               'status': pf_entry['status']}
        return self._fields(res, fields)

    def _get_packet_filter(self, context, id):
        try:
            pf_entry = self._get_by_id(context, PacketFilter, id)
        except sa_exc.NoResultFound:
            raise PacketFilterNotFound(id=id)
        return pf_entry

    def get_packet_filter(self, context, id, fields=None):
        pf_entry = self._get_packet_filter(context, id)
        return self._make_packet_filter_dict(pf_entry, fields)

    def get_packet_filters(self, context, filters=None, fields=None):
        return self._get_collection(context,
                                    PacketFilter,
                                    self._make_packet_filter_dict,
                                    filters=filters,
                                    fields=fields)

    def create_packet_filter(self, context, packet_filter):
        pf_dict = packet_filter['packet_filter']
        tenant_id = self._get_tenant_id_for_create(context, pf_dict)

        if pf_dict['in_port'] == attributes.ATTR_NOT_SPECIFIED:
            # validate network ownership
            self.get_network(context, pf_dict['network_id'])
        else:
            # validate port ownership
            self.get_port(context, pf_dict['in_port'])

        params = {'tenant_id': tenant_id,
                  'id': pf_dict.get('id') or uuidutils.generate_uuid(),
                  'name': pf_dict['name'],
                  'network_id': pf_dict['network_id'],
                  'priority': pf_dict['priority'],
                  'action': pf_dict['action'],
                  'admin_state_up': pf_dict.get('admin_state_up', True),
                  'status': PF_STATUS_DOWN,
                  'in_port': pf_dict['in_port'],
                  'src_mac': pf_dict['src_mac'],
                  'dst_mac': pf_dict['dst_mac'],
                  'eth_type': pf_dict['eth_type'],
                  'src_cidr': pf_dict['src_cidr'],
                  'dst_cidr': pf_dict['dst_cidr'],
                  'src_port': pf_dict['src_port'],
                  'dst_port': pf_dict['dst_port'],
                  'protocol': pf_dict['protocol']}
        for key, default in params.items():
            if params[key] == attributes.ATTR_NOT_SPECIFIED:
                if key == 'in_port':
                    params[key] = None
                else:
                    params[key] = ''

        with context.session.begin(subtransactions=True):
            pf_entry = PacketFilter(**params)
            context.session.add(pf_entry)

        return self._make_packet_filter_dict(pf_entry)

    def update_packet_filter(self, context, id, packet_filter):
        pf = packet_filter['packet_filter']
        with context.session.begin(subtransactions=True):
            pf_entry = self._get_packet_filter(context, id)
            pf_entry.update(pf)
        return self._make_packet_filter_dict(pf_entry)

    def delete_packet_filter(self, context, id):
        with context.session.begin(subtransactions=True):
            pf_entry = self._get_packet_filter(context, id)
            context.session.delete(pf_entry)

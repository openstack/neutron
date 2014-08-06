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

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc as sa_exc
from sqlalchemy import sql

from neutron.api.v2 import attributes
from neutron.db import model_base
from neutron.db import models_v2
from neutron.openstack.common import uuidutils
from neutron.plugins.nec.db import models as nmodels
from neutron.plugins.nec.extensions import packetfilter as ext_pf


PF_STATUS_ACTIVE = 'ACTIVE'
PF_STATUS_DOWN = 'DOWN'
PF_STATUS_ERROR = 'ERROR'

INT_FIELDS = ('eth_type', 'src_port', 'dst_port')


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
               # "or None" ensure the filed is None if empty
               'src_mac': pf_entry['src_mac'] or None,
               'dst_mac': pf_entry['dst_mac'] or None,
               'eth_type': pf_entry['eth_type'] or None,
               'src_cidr': pf_entry['src_cidr'] or None,
               'dst_cidr': pf_entry['dst_cidr'] or None,
               'protocol': pf_entry['protocol'] or None,
               'src_port': pf_entry['src_port'] or None,
               'dst_port': pf_entry['dst_port'] or None,
               'admin_state_up': pf_entry['admin_state_up'],
               'status': pf_entry['status']}
        return self._fields(res, fields)

    def _get_packet_filter(self, context, id):
        try:
            pf_entry = self._get_by_id(context, PacketFilter, id)
        except sa_exc.NoResultFound:
            raise ext_pf.PacketFilterNotFound(id=id)
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

    def _replace_unspecified_field(self, params, key):
        if not attributes.is_attr_set(params[key]):
            if key == 'in_port':
                params[key] = None
            elif key in INT_FIELDS:
                # Integer field
                params[key] = 0
            else:
                params[key] = ''

    def _get_eth_type_for_protocol(self, protocol):
        if protocol.upper() in ("ICMP", "TCP", "UDP"):
            return 0x800
        elif protocol.upper() == "ARP":
            return 0x806

    def _set_eth_type_from_protocol(self, filter_dict):
        if filter_dict.get('protocol'):
            eth_type = self._get_eth_type_for_protocol(filter_dict['protocol'])
            if eth_type:
                filter_dict['eth_type'] = eth_type

    def _check_eth_type_and_protocol(self, new_filter, current_filter):
        if 'protocol' in new_filter or 'eth_type' not in new_filter:
            return
        eth_type = self._get_eth_type_for_protocol(current_filter['protocol'])
        if not eth_type:
            return
        if eth_type != new_filter['eth_type']:
            raise ext_pf.PacketFilterEtherTypeProtocolMismatch(
                eth_type=hex(new_filter['eth_type']),
                protocol=current_filter['protocol'])

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
        for key in params:
            self._replace_unspecified_field(params, key)
        self._set_eth_type_from_protocol(params)

        with context.session.begin(subtransactions=True):
            pf_entry = PacketFilter(**params)
            context.session.add(pf_entry)

        return self._make_packet_filter_dict(pf_entry)

    def update_packet_filter(self, context, id, packet_filter):
        params = packet_filter['packet_filter']
        for key in params:
            self._replace_unspecified_field(params, key)
        self._set_eth_type_from_protocol(params)
        with context.session.begin(subtransactions=True):
            pf_entry = self._get_packet_filter(context, id)
            self._check_eth_type_and_protocol(params, pf_entry)
            pf_entry.update(params)
        return self._make_packet_filter_dict(pf_entry)

    def delete_packet_filter(self, context, id):
        with context.session.begin(subtransactions=True):
            pf_entry = self._get_packet_filter(context, id)
            context.session.delete(pf_entry)

    def get_packet_filters_for_port(self, context, port):
        """Retrieve packet filters on OFC on a given port.

        It returns a list of tuple (neutron filter_id, OFC id).
        """
        query = (context.session.query(nmodels.OFCFilterMapping)
                 .join(PacketFilter,
                       nmodels.OFCFilterMapping.neutron_id == PacketFilter.id)
                 .filter(PacketFilter.admin_state_up == sql.true()))

        network_id = port['network_id']
        net_pf_query = (query.filter(PacketFilter.network_id == network_id)
                        .filter(PacketFilter.in_port == sql.null()))
        net_filters = [(pf['neutron_id'], pf['ofc_id']) for pf in net_pf_query]

        port_pf_query = query.filter(PacketFilter.in_port == port['id'])
        port_filters = [(pf['neutron_id'], pf['ofc_id'])
                        for pf in port_pf_query]

        return net_filters + port_filters

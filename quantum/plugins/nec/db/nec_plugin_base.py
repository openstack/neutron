# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 NEC Corporation.  All rights reserved.
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

import logging

from sqlalchemy.orm import exc

from quantum.api.v2 import attributes
from quantum.common import utils
from quantum.db import db_base_plugin_v2
from quantum.plugins.nec.common import exceptions as q_exc
from quantum.plugins.nec.db import models as nmodels


LOG = logging.getLogger(__name__)


class NECPluginV2Base(db_base_plugin_v2.QuantumDbPluginV2):

    """ Base class of plugins that handle packet filters. """

    def _make_packet_filter_dict(self, packet_filter, fields=None):
        res = {'id': packet_filter['id'],
               'tenant_id': packet_filter['tenant_id'],
               'network_id': packet_filter['network_id'],
               'action': packet_filter['action'],
               'priority': packet_filter['priority'],
               'in_port': packet_filter['in_port'],
               'src_mac': packet_filter['src_mac'],
               'dst_mac': packet_filter['dst_mac'],
               'eth_type': packet_filter['eth_type'],
               'src_cidr': packet_filter['src_cidr'],
               'dst_cidr': packet_filter['dst_cidr'],
               'protocol': packet_filter['protocol'],
               'src_port': packet_filter['src_port'],
               'dst_port': packet_filter['dst_port'],
               'admin_state_up': packet_filter['admin_state_up'],
               'status': packet_filter['status']}
        return self._fields(res, fields)

    def _get_packet_filter(self, context, id):
        try:
            packet_filter = self._get_by_id(context, nmodels.PacketFilter, id)
        except exc.NoResultFound:
            raise q_exc.PacketFilterNotFound(id=id)
        except exc.MultipleResultsFound:
            LOG.error('Multiple packet_filters match for %s' % id)
            raise q_exc.PacketFilterNotFound(id=id)
        return packet_filter

    def get_packet_filter(self, context, id, fields=None):
        packet_filter = self._get_packet_filter(context, id)
        return self._make_packet_filter_dict(packet_filter, fields)

    def get_packet_filters(self, context, filters=None, fields=None):
        return self._get_collection(context,
                                    nmodels.PacketFilter,
                                    self._make_packet_filter_dict,
                                    filters=filters,
                                    fields=fields)

    def create_packet_filter(self, context, packet_filter):
        pf = packet_filter['packet_filter']
        tenant_id = self._get_tenant_id_for_create(context, pf)

        # validate network ownership
        super(NECPluginV2Base, self).get_network(context, pf['network_id'])
        if pf.get('in_port') != attributes.ATTR_NOT_SPECIFIED:
            # validate port ownership
            super(NECPluginV2Base, self).get_port(context, pf['in_port'])

        params = {'tenant_id': tenant_id,
                  'id': pf.get('id') or utils.str_uuid(),
                  'network_id': pf['network_id'],
                  'priority': pf['priority'],
                  'action': pf['action'],
                  'admin_state_up': pf.get('admin_state_up', True),
                  'status': "ACTIVE"}
        conditions = {'in_port': '',
                      'src_mac': '',
                      'dst_mac': '',
                      'eth_type': 0,
                      'src_cidr': '',
                      'dst_cidr': '',
                      'src_port': 0,
                      'dst_port': 0,
                      'protocol': ''}
        for key, default in conditions.items():
            if pf.get(key) == attributes.ATTR_NOT_SPECIFIED:
                params.update({key: default})
            else:
                params.update({key: pf.get(key)})

        with context.session.begin():
            pf_entry = nmodels.PacketFilter(**params)
            context.session.add(pf_entry)
        return self._make_packet_filter_dict(pf_entry)

    def update_packet_filter(self, context, id, packet_filter):
        pf = packet_filter['packet_filter']
        with context.session.begin():
            pf_entry = self._get_packet_filter(context, id)
            pf_entry.update(pf)
        return self._make_packet_filter_dict(pf_entry)

    def delete_packet_filter(self, context, id):
        with context.session.begin():
            packet_filter = self._get_packet_filter(context, id)
            context.session.delete(packet_filter)

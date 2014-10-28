# Copyright (c) 2013 OpenStack Foundation.
# All Rights Reserved.
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
from sqlalchemy.orm import exc
from sqlalchemy.sql import expression as expr

from neutron.api.v2 import attributes
from neutron.common import constants as l3_constants
from neutron.common import exceptions as n_exc
from neutron.db import db_base_plugin_v2
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import external_net
from neutron import manager
from neutron.plugins.common import constants as service_constants


DEVICE_OWNER_ROUTER_GW = l3_constants.DEVICE_OWNER_ROUTER_GW


class ExternalNetwork(model_base.BASEV2):
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)

    # Add a relationship to the Network model in order to instruct
    # SQLAlchemy to eagerly load this association
    network = orm.relationship(
        models_v2.Network,
        backref=orm.backref("external", lazy='joined',
                            uselist=False, cascade='delete'))


class External_net_db_mixin(object):
    """Mixin class to add external network methods to db_base_plugin_v2."""

    def _network_model_hook(self, context, original_model, query):
        query = query.outerjoin(ExternalNetwork,
                                (original_model.id ==
                                 ExternalNetwork.network_id))
        return query

    def _network_filter_hook(self, context, original_model, conditions):
        if conditions is not None and not hasattr(conditions, '__iter__'):
            conditions = (conditions, )
        # Apply the external network filter only in non-admin and non-advsvc
        # context
        if self.model_query_scope(context, original_model):
            conditions = expr.or_(ExternalNetwork.network_id != expr.null(),
                                  *conditions)
        return conditions

    def _network_result_filter_hook(self, query, filters):
        vals = filters and filters.get(external_net.EXTERNAL, [])
        if not vals:
            return query
        if vals[0]:
            return query.filter((ExternalNetwork.network_id != expr.null()))
        return query.filter((ExternalNetwork.network_id == expr.null()))

    # TODO(salvatore-orlando): Perform this operation without explicitly
    # referring to db_base_plugin_v2, as plugins that do not extend from it
    # might exist in the future
    db_base_plugin_v2.NeutronDbPluginV2.register_model_query_hook(
        models_v2.Network,
        "external_net",
        '_network_model_hook',
        '_network_filter_hook',
        '_network_result_filter_hook')

    def _network_is_external(self, context, net_id):
        try:
            context.session.query(ExternalNetwork).filter_by(
                network_id=net_id).one()
            return True
        except exc.NoResultFound:
            return False

    def _extend_network_dict_l3(self, network_res, network_db):
        # Comparing with None for converting uuid into bool
        network_res[external_net.EXTERNAL] = network_db.external is not None
        return network_res

    # Register dict extend functions for networks
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attributes.NETWORKS, ['_extend_network_dict_l3'])

    def _process_l3_create(self, context, net_data, req_data):
        external = req_data.get(external_net.EXTERNAL)
        external_set = attributes.is_attr_set(external)

        if not external_set:
            return

        if external:
            # expects to be called within a plugin's session
            context.session.add(ExternalNetwork(network_id=net_data['id']))
        net_data[external_net.EXTERNAL] = external

    def _process_l3_update(self, context, net_data, req_data):

        new_value = req_data.get(external_net.EXTERNAL)
        net_id = net_data['id']
        if not attributes.is_attr_set(new_value):
            return

        if net_data.get(external_net.EXTERNAL) == new_value:
            return

        if new_value:
            context.session.add(ExternalNetwork(network_id=net_id))
            net_data[external_net.EXTERNAL] = True
        else:
            # must make sure we do not have any external gateway ports
            # (and thus, possible floating IPs) on this network before
            # allow it to be update to external=False
            port = context.session.query(models_v2.Port).filter_by(
                device_owner=DEVICE_OWNER_ROUTER_GW,
                network_id=net_data['id']).first()
            if port:
                raise external_net.ExternalNetworkInUse(net_id=net_id)

            context.session.query(ExternalNetwork).filter_by(
                network_id=net_id).delete()
            net_data[external_net.EXTERNAL] = False

    def _process_l3_delete(self, context, network_id):
        l3plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        if l3plugin:
            l3plugin.delete_disassociated_floatingips(context, network_id)

    def _filter_nets_l3(self, context, nets, filters):
        vals = filters and filters.get(external_net.EXTERNAL, [])
        if not vals:
            return nets

        ext_nets = set(en['network_id']
                       for en in context.session.query(ExternalNetwork))
        if vals[0]:
            return [n for n in nets if n['id'] in ext_nets]
        else:
            return [n for n in nets if n['id'] not in ext_nets]

    def get_external_network_id(self, context):
        nets = self.get_networks(context, {external_net.EXTERNAL: [True]})
        if len(nets) > 1:
            raise n_exc.TooManyExternalNetworks()
        else:
            return nets[0]['id'] if nets else None

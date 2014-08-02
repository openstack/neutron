# Copyright 2013 VMware, Inc.  All rights reserved.
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

from neutron.api.v2 import attributes as attrs
from neutron.db import db_base_plugin_v2
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import portsecurity as psec
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class PortSecurityBinding(model_base.BASEV2):
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    port_security_enabled = sa.Column(sa.Boolean(), nullable=False)

    # Add a relationship to the Port model in order to be to able to
    # instruct SQLAlchemy to eagerly load port security binding
    port = orm.relationship(
        models_v2.Port,
        backref=orm.backref("port_security", uselist=False,
                            cascade='delete', lazy='joined'))


class NetworkSecurityBinding(model_base.BASEV2):
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    port_security_enabled = sa.Column(sa.Boolean(), nullable=False)

    # Add a relationship to the Port model in order to be able to instruct
    # SQLAlchemy to eagerly load default port security setting for ports
    # on this network
    network = orm.relationship(
        models_v2.Network,
        backref=orm.backref("port_security", uselist=False,
                            cascade='delete', lazy='joined'))


class PortSecurityDbMixin(object):
    """Mixin class to add port security."""

    def _process_network_port_security_create(
        self, context, network_req, network_res):
        with context.session.begin(subtransactions=True):
            db = NetworkSecurityBinding(
                network_id=network_res['id'],
                port_security_enabled=network_req[psec.PORTSECURITY])
            context.session.add(db)
        network_res[psec.PORTSECURITY] = network_req[psec.PORTSECURITY]
        return self._make_network_port_security_dict(db)

    def _process_port_port_security_create(
        self, context, port_req, port_res):
        with context.session.begin(subtransactions=True):
            db = PortSecurityBinding(
                port_id=port_res['id'],
                port_security_enabled=port_req[psec.PORTSECURITY])
            context.session.add(db)
        port_res[psec.PORTSECURITY] = port_req[psec.PORTSECURITY]
        return self._make_port_security_dict(db)

    def _extend_port_security_dict(self, response_data, db_data):
        if ('port-security' in
            getattr(self, 'supported_extension_aliases', [])):
            psec_value = db_data['port_security'][psec.PORTSECURITY]
            response_data[psec.PORTSECURITY] = psec_value

    def _get_network_security_binding(self, context, network_id):
        try:
            query = self._model_query(context, NetworkSecurityBinding)
            binding = query.filter(
                NetworkSecurityBinding.network_id == network_id).one()
        except exc.NoResultFound:
            raise psec.PortSecurityBindingNotFound()
        return binding[psec.PORTSECURITY]

    def _get_port_security_binding(self, context, port_id):
        try:
            query = self._model_query(context, PortSecurityBinding)
            binding = query.filter(
                PortSecurityBinding.port_id == port_id).one()
        except exc.NoResultFound:
            raise psec.PortSecurityBindingNotFound()
        return binding[psec.PORTSECURITY]

    def _process_port_port_security_update(
        self, context, port_req, port_res):
        if psec.PORTSECURITY in port_req:
            port_security_enabled = port_req[psec.PORTSECURITY]
        else:
            return
        try:
            query = self._model_query(context, PortSecurityBinding)
            port_id = port_res['id']
            binding = query.filter(
                PortSecurityBinding.port_id == port_id).one()

            binding.port_security_enabled = port_security_enabled
            port_res[psec.PORTSECURITY] = port_security_enabled
        except exc.NoResultFound:
            raise psec.PortSecurityBindingNotFound()

    def _process_network_port_security_update(
        self, context, network_req, network_res):
        if psec.PORTSECURITY in network_req:
            port_security_enabled = network_req[psec.PORTSECURITY]
        else:
            return
        try:
            query = self._model_query(context, NetworkSecurityBinding)
            network_id = network_res['id']
            binding = query.filter(
                NetworkSecurityBinding.network_id == network_id).one()

            binding.port_security_enabled = port_security_enabled
            network_res[psec.PORTSECURITY] = port_security_enabled
        except exc.NoResultFound:
            raise psec.PortSecurityBindingNotFound()

    def _make_network_port_security_dict(self, port_security, fields=None):
        res = {'network_id': port_security['network_id'],
               psec.PORTSECURITY: port_security[psec.PORTSECURITY]}
        return self._fields(res, fields)

    def _determine_port_security_and_has_ip(self, context, port):
        """Returns a tuple of booleans (port_security_enabled, has_ip).

        Port_security is the value associated with the port if one is present
        otherwise the value associated with the network is returned. has_ip is
        if the port is associated with an ip or not.
        """
        has_ip = self._ip_on_port(port)
        # we don't apply security groups for dhcp, router
        if (port.get('device_owner') and
                port['device_owner'].startswith('network:')):
            return (False, has_ip)

        if (psec.PORTSECURITY in port and
            isinstance(port[psec.PORTSECURITY], bool)):
            port_security_enabled = port[psec.PORTSECURITY]

        # If port has an ip and security_groups are passed in
        # conveniently set port_security_enabled to true this way
        # user doesn't also have to pass in port_security_enabled=True
        # when creating ports.
        elif (has_ip and attrs.is_attr_set('security_groups')):
            port_security_enabled = True
        else:
            port_security_enabled = self._get_network_security_binding(
                context, port['network_id'])

        return (port_security_enabled, has_ip)

    def _make_port_security_dict(self, port, fields=None):
        res = {'port_id': port['port_id'],
               psec.PORTSECURITY: port[psec.PORTSECURITY]}
        return self._fields(res, fields)

    def _ip_on_port(self, port):
        return bool(port.get('fixed_ips'))

    # Register dict extend functions for ports and networks
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attrs.NETWORKS, ['_extend_port_security_dict'])
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attrs.PORTS, ['_extend_port_security_dict'])

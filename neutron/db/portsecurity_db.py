# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Nicira Networks, Inc.  All rights reserved.
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
#
# @author: Aaron Rosen, Nicira, Inc

import sqlalchemy as sa
from sqlalchemy.orm import exc

from neutron.db import model_base
from neutron.extensions import portsecurity as psec
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class PortSecurityBinding(model_base.BASEV2):
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    port_security_enabled = sa.Column(sa.Boolean(), nullable=False)


class NetworkSecurityBinding(model_base.BASEV2):
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    port_security_enabled = sa.Column(sa.Boolean(), nullable=False)


class PortSecurityDbMixin(object):
    """Mixin class to add port security."""

    def _process_network_create_port_security(self, context, network):
        with context.session.begin(subtransactions=True):
            db = NetworkSecurityBinding(
                network_id=network['id'],
                port_security_enabled=network[psec.PORTSECURITY])
            context.session.add(db)
        return self._make_network_port_security_dict(db)

    def _extend_network_port_security_dict(self, context, network):
        network[psec.PORTSECURITY] = self._get_network_security_binding(
            context, network['id'])

    def _extend_port_port_security_dict(self, context, port):
        port[psec.PORTSECURITY] = self._get_port_security_binding(
            context, port['id'])

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

    def _update_port_security_binding(self, context, port_id,
                                      port_security_enabled):
        try:
            query = self._model_query(context, PortSecurityBinding)
            binding = query.filter(
                PortSecurityBinding.port_id == port_id).one()

            binding.update({psec.PORTSECURITY: port_security_enabled})
        except exc.NoResultFound:
            raise psec.PortSecurityBindingNotFound()

    def _update_network_security_binding(self, context, network_id,
                                         port_security_enabled):
        try:
            query = self._model_query(context, NetworkSecurityBinding)
            binding = query.filter(
                NetworkSecurityBinding.network_id == network_id).one()

            binding.update({psec.PORTSECURITY: port_security_enabled})
        except exc.NoResultFound:
            raise psec.PortSecurityBindingNotFound()

    def _make_network_port_security_dict(self, port_security, fields=None):
        res = {'network_id': port_security['network_id'],
               psec.PORTSECURITY: port_security[psec.PORTSECURITY]}
        return self._fields(res, fields)

    def _determine_port_security_and_has_ip(self, context, port):
        """Returns a tuple of booleans (port_security_enabled, has_ip).

        Port_security is the value assocated with the port if one is present
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
        else:
            port_security_enabled = self._get_network_security_binding(
                context, port['network_id'])

        return (port_security_enabled, has_ip)

    def _process_port_security_create(self, context, port):
        with context.session.begin(subtransactions=True):
            port_security_binding = PortSecurityBinding(
                port_id=port['id'],
                port_security_enabled=port[psec.PORTSECURITY])
            context.session.add(port_security_binding)
        return self._make_port_security_dict(port_security_binding)

    def _make_port_security_dict(self, port, fields=None):
        res = {'port_id': port['port_id'],
               psec.PORTSECURITY: port[psec.PORTSECURITY]}
        return self._fields(res, fields)

    def _ip_on_port(self, port):
        return bool(port.get('fixed_ips'))

# Copyright (c) 2013 OpenStack Foundation
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

from oslo_config import cfg
from oslo_log import log
import sqlalchemy as sa
from sqlalchemy import sql

from neutron.common import exceptions as n_exc
from neutron.db import model_base
from neutron.i18n import _LE
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers import type_tunnel

LOG = log.getLogger(__name__)

gre_opts = [
    cfg.ListOpt('tunnel_id_ranges',
                default=[],
                help=_("Comma-separated list of <tun_min>:<tun_max> tuples "
                       "enumerating ranges of GRE tunnel IDs that are "
                       "available for tenant network allocation"))
]

cfg.CONF.register_opts(gre_opts, "ml2_type_gre")


class GreAllocation(model_base.BASEV2):

    __tablename__ = 'ml2_gre_allocations'

    gre_id = sa.Column(sa.Integer, nullable=False, primary_key=True,
                       autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False,
                          server_default=sql.false(), index=True)


class GreEndpoints(model_base.BASEV2):
    """Represents tunnel endpoint in RPC mode."""

    __tablename__ = 'ml2_gre_endpoints'
    __table_args__ = (
        sa.UniqueConstraint('host',
                            name='unique_ml2_gre_endpoints0host'),
        model_base.BASEV2.__table_args__
    )
    ip_address = sa.Column(sa.String(64), primary_key=True)
    host = sa.Column(sa.String(255), nullable=True)

    def __repr__(self):
        return "<GreTunnelEndpoint(%s)>" % self.ip_address


class GreTypeDriver(type_tunnel.EndpointTunnelTypeDriver):

    def __init__(self):
        super(GreTypeDriver, self).__init__(
            GreAllocation, GreEndpoints)

    def get_type(self):
        return p_const.TYPE_GRE

    def initialize(self):
        try:
            self._initialize(cfg.CONF.ml2_type_gre.tunnel_id_ranges)
        except n_exc.NetworkTunnelRangeError:
            LOG.exception(_LE("Failed to parse tunnel_id_ranges. "
                              "Service terminated!"))
            raise SystemExit()

    def get_endpoints(self):
        """Get every gre endpoints from database."""
        gre_endpoints = self._get_endpoints()
        return [{'ip_address': gre_endpoint.ip_address,
                 'host': gre_endpoint.host}
                for gre_endpoint in gre_endpoints]

    def add_endpoint(self, ip, host):
        return self._add_endpoint(ip, host)

    def get_mtu(self, physical_network=None):
        mtu = super(GreTypeDriver, self).get_mtu(physical_network)
        return mtu - p_const.GRE_ENCAP_OVERHEAD if mtu else 0

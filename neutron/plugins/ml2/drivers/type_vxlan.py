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

vxlan_opts = [
    cfg.ListOpt('vni_ranges',
                default=[],
                help=_("Comma-separated list of <vni_min>:<vni_max> tuples "
                       "enumerating ranges of VXLAN VNI IDs that are "
                       "available for tenant network allocation")),
    cfg.StrOpt('vxlan_group',
               help=_("Multicast group for VXLAN. If unset, disables VXLAN "
                      "multicast mode.")),
]

cfg.CONF.register_opts(vxlan_opts, "ml2_type_vxlan")


class VxlanAllocation(model_base.BASEV2):

    __tablename__ = 'ml2_vxlan_allocations'

    vxlan_vni = sa.Column(sa.Integer, nullable=False, primary_key=True,
                          autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False,
                          server_default=sql.false(), index=True)


class VxlanEndpoints(model_base.BASEV2):
    """Represents tunnel endpoint in RPC mode."""

    __tablename__ = 'ml2_vxlan_endpoints'
    __table_args__ = (
        sa.UniqueConstraint('host',
                            name='unique_ml2_vxlan_endpoints0host'),
        model_base.BASEV2.__table_args__
    )
    ip_address = sa.Column(sa.String(64), primary_key=True)
    udp_port = sa.Column(sa.Integer, nullable=False)
    host = sa.Column(sa.String(255), nullable=True)

    def __repr__(self):
        return "<VxlanTunnelEndpoint(%s)>" % self.ip_address


class VxlanTypeDriver(type_tunnel.EndpointTunnelTypeDriver):

    def __init__(self):
        super(VxlanTypeDriver, self).__init__(
            VxlanAllocation, VxlanEndpoints)

    def get_type(self):
        return p_const.TYPE_VXLAN

    def initialize(self):
        try:
            self._initialize(cfg.CONF.ml2_type_vxlan.vni_ranges)
        except n_exc.NetworkTunnelRangeError:
            LOG.exception(_LE("Failed to parse vni_ranges. "
                              "Service terminated!"))
            raise SystemExit()

    def get_endpoints(self):
        """Get every vxlan endpoints from database."""
        vxlan_endpoints = self._get_endpoints()
        return [{'ip_address': vxlan_endpoint.ip_address,
                 'udp_port': vxlan_endpoint.udp_port,
                 'host': vxlan_endpoint.host}
                for vxlan_endpoint in vxlan_endpoints]

    def add_endpoint(self, ip, host, udp_port=p_const.VXLAN_UDP_PORT):
        return self._add_endpoint(ip, host, udp_port=udp_port)

    def get_mtu(self, physical_network=None):
        mtu = super(VxlanTypeDriver, self).get_mtu()
        return mtu - p_const.VXLAN_ENCAP_OVERHEAD if mtu else 0

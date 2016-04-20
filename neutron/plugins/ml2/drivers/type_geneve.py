# Copyright (c) 2015 OpenStack Foundation
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

from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log
import sqlalchemy as sa
from sqlalchemy import sql

from neutron._i18n import _, _LE
from neutron.db import model_base
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers import type_tunnel

LOG = log.getLogger(__name__)

geneve_opts = [
    cfg.ListOpt('vni_ranges',
                default=[],
                help=_("Comma-separated list of <vni_min>:<vni_max> tuples "
                       "enumerating ranges of Geneve VNI IDs that are "
                       "available for tenant network allocation")),
    cfg.IntOpt('max_header_size',
               default=p_const.GENEVE_ENCAP_MIN_OVERHEAD,
               help=_("Geneve encapsulation header size is dynamic, this "
                      "value is used to calculate the maximum MTU "
                      "for the driver. "
                      "This is the sum of the sizes of the outer "
                      "ETH + IP + UDP + GENEVE header sizes. "
                      "The default size for this field is 50, which is the "
                      "size of the Geneve header without any additional "
                      "option headers.")),
]

cfg.CONF.register_opts(geneve_opts, "ml2_type_geneve")


class GeneveAllocation(model_base.BASEV2):

    __tablename__ = 'ml2_geneve_allocations'

    geneve_vni = sa.Column(sa.Integer, nullable=False, primary_key=True,
                        autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False,
                          server_default=sql.false(), index=True)


class GeneveEndpoints(model_base.BASEV2):
    """Represents tunnel endpoint in RPC mode."""

    __tablename__ = 'ml2_geneve_endpoints'
    __table_args__ = (
        sa.UniqueConstraint('host',
                            name='unique_ml2_geneve_endpoints0host'),
        model_base.BASEV2.__table_args__
    )
    ip_address = sa.Column(sa.String(64), primary_key=True)
    host = sa.Column(sa.String(255), nullable=True)

    def __repr__(self):
        return "<GeneveTunnelEndpoint(%s)>" % self.ip_address


class GeneveTypeDriver(type_tunnel.EndpointTunnelTypeDriver):

    def __init__(self):
        super(GeneveTypeDriver, self).__init__(GeneveAllocation,
                                               GeneveEndpoints)
        self.max_encap_size = cfg.CONF.ml2_type_geneve.max_header_size

    def get_type(self):
        return p_const.TYPE_GENEVE

    def initialize(self):
        try:
            self._initialize(cfg.CONF.ml2_type_geneve.vni_ranges)
        except n_exc.NetworkTunnelRangeError:
            LOG.error(_LE("Failed to parse vni_ranges. "
                          "Service terminated!"))
            raise SystemExit()

    def get_endpoints(self):
        """Get every geneve endpoints from database."""
        geneve_endpoints = self._get_endpoints()
        return [{'ip_address': geneve_endpoint.ip_address,
                 'host': geneve_endpoint.host}
                for geneve_endpoint in geneve_endpoints]

    def add_endpoint(self, ip, host):
        return self._add_endpoint(ip, host)

    def get_mtu(self, physical_network=None):
        mtu = super(GeneveTypeDriver, self).get_mtu()
        return mtu - self.max_encap_size if mtu else 0

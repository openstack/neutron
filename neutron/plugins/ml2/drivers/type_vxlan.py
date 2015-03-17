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
from oslo_db import exception as db_exc
from oslo_log import log
from six import moves
import sqlalchemy as sa
from sqlalchemy import sql

from neutron.common import exceptions as n_exc
from neutron.db import api as db_api
from neutron.db import model_base
from neutron.i18n import _LE, _LW
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers import type_tunnel

LOG = log.getLogger(__name__)

VXLAN_UDP_PORT = 4789
MAX_VXLAN_VNI = 16777215

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


class VxlanTypeDriver(type_tunnel.TunnelTypeDriver):

    def __init__(self):
        super(VxlanTypeDriver, self).__init__(VxlanAllocation)

    def get_type(self):
        return p_const.TYPE_VXLAN

    def initialize(self):
        try:
            self._initialize(cfg.CONF.ml2_type_vxlan.vni_ranges)
        except n_exc.NetworkTunnelRangeError:
            LOG.exception(_LE("Failed to parse vni_ranges. "
                              "Service terminated!"))
            raise SystemExit()

    def sync_allocations(self):

        # determine current configured allocatable vnis
        vxlan_vnis = set()
        for tun_min, tun_max in self.tunnel_ranges:
            if tun_max + 1 - tun_min > MAX_VXLAN_VNI:
                LOG.error(_LE("Skipping unreasonable VXLAN VNI range "
                              "%(tun_min)s:%(tun_max)s"),
                          {'tun_min': tun_min, 'tun_max': tun_max})
            else:
                vxlan_vnis |= set(moves.xrange(tun_min, tun_max + 1))

        session = db_api.get_session()
        with session.begin(subtransactions=True):
            # remove from table unallocated tunnels not currently allocatable
            # fetch results as list via all() because we'll be iterating
            # through them twice
            allocs = (session.query(VxlanAllocation).
                      with_lockmode("update").all())
            # collect all vnis present in db
            existing_vnis = set(alloc.vxlan_vni for alloc in allocs)
            # collect those vnis that needs to be deleted from db
            vnis_to_remove = [alloc.vxlan_vni for alloc in allocs
                              if (alloc.vxlan_vni not in vxlan_vnis and
                                  not alloc.allocated)]
            # Immediately delete vnis in chunks. This leaves no work for
            # flush at the end of transaction
            bulk_size = 100
            chunked_vnis = (vnis_to_remove[i:i + bulk_size] for i in
                            range(0, len(vnis_to_remove), bulk_size))
            for vni_list in chunked_vnis:
                if vni_list:
                    session.query(VxlanAllocation).filter(
                        VxlanAllocation.vxlan_vni.in_(vni_list)).delete(
                            synchronize_session=False)
            # collect vnis that need to be added
            vnis = list(vxlan_vnis - existing_vnis)
            chunked_vnis = (vnis[i:i + bulk_size] for i in
                            range(0, len(vnis), bulk_size))
            for vni_list in chunked_vnis:
                bulk = [{'vxlan_vni': vni, 'allocated': False}
                        for vni in vni_list]
                session.execute(VxlanAllocation.__table__.insert(), bulk)

    def get_endpoints(self):
        """Get every vxlan endpoints from database."""

        LOG.debug("get_vxlan_endpoints() called")
        session = db_api.get_session()

        vxlan_endpoints = session.query(VxlanEndpoints)
        return [{'ip_address': vxlan_endpoint.ip_address,
                 'udp_port': vxlan_endpoint.udp_port,
                 'host': vxlan_endpoint.host}
                for vxlan_endpoint in vxlan_endpoints]

    def get_endpoint_by_host(self, host):
        LOG.debug("get_endpoint_by_host() called for host %s", host)
        session = db_api.get_session()
        return (session.query(VxlanEndpoints).
                filter_by(host=host).first())

    def get_endpoint_by_ip(self, ip):
        LOG.debug("get_endpoint_by_ip() called for ip %s", ip)
        session = db_api.get_session()
        return (session.query(VxlanEndpoints).
                filter_by(ip_address=ip).first())

    def add_endpoint(self, ip, host, udp_port=VXLAN_UDP_PORT):
        LOG.debug("add_vxlan_endpoint() called for ip %s", ip)
        session = db_api.get_session()
        try:
            vxlan_endpoint = VxlanEndpoints(ip_address=ip,
                                            udp_port=udp_port,
                                            host=host)
            vxlan_endpoint.save(session)
        except db_exc.DBDuplicateEntry:
            vxlan_endpoint = (session.query(VxlanEndpoints).
                              filter_by(ip_address=ip).one())
            LOG.warning(_LW("Vxlan endpoint with ip %s already exists"), ip)
        return vxlan_endpoint

    def delete_endpoint(self, ip):
        LOG.debug("delete_vxlan_endpoint() called for ip %s", ip)
        session = db_api.get_session()

        with session.begin(subtransactions=True):
            session.query(VxlanEndpoints).filter_by(ip_address=ip).delete()

    def get_mtu(self, physical_network=None):
        mtu = super(VxlanTypeDriver, self).get_mtu()
        return mtu - p_const.VXLAN_ENCAP_OVERHEAD if mtu else 0

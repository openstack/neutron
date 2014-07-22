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
# @author: Kyle Mestery, Cisco Systems, Inc.

from oslo.config import cfg
import sqlalchemy as sa
from sqlalchemy.orm import exc as sa_exc
from sqlalchemy import sql

from neutron.common import exceptions as exc
from neutron.db import api as db_api
from neutron.db import model_base
from neutron.openstack.common import log
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import helpers
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
                          server_default=sql.false())


class VxlanEndpoints(model_base.BASEV2):
    """Represents tunnel endpoint in RPC mode."""
    __tablename__ = 'ml2_vxlan_endpoints'

    ip_address = sa.Column(sa.String(64), primary_key=True)
    udp_port = sa.Column(sa.Integer, primary_key=True, nullable=False,
                         autoincrement=False)

    def __repr__(self):
        return "<VxlanTunnelEndpoint(%s)>" % self.ip_address


class VxlanTypeDriver(helpers.TypeDriverHelper, type_tunnel.TunnelTypeDriver):

    def __init__(self):
        super(VxlanTypeDriver, self).__init__(VxlanAllocation)

    def get_type(self):
        return p_const.TYPE_VXLAN

    def initialize(self):
        self.vxlan_vni_ranges = []
        self._parse_tunnel_ranges(
            cfg.CONF.ml2_type_vxlan.vni_ranges,
            self.vxlan_vni_ranges,
            p_const.TYPE_VXLAN
        )
        self._sync_vxlan_allocations()

    def reserve_provider_segment(self, session, segment):
        if self.is_partial_segment(segment):
            alloc = self.allocate_partially_specified_segment(session)
            if not alloc:
                raise exc.NoNetworkAvailable
        else:
            segmentation_id = segment.get(api.SEGMENTATION_ID)
            alloc = self.allocate_fully_specified_segment(
                session, vxlan_vni=segmentation_id)
            if not alloc:
                raise exc.TunnelIdInUse(tunnel_id=segmentation_id)
        return {api.NETWORK_TYPE: p_const.TYPE_VXLAN,
                api.PHYSICAL_NETWORK: None,
                api.SEGMENTATION_ID: alloc.vxlan_vni}

    def allocate_tenant_segment(self, session):
        alloc = self.allocate_partially_specified_segment(session)
        if not alloc:
            return
        return {api.NETWORK_TYPE: p_const.TYPE_VXLAN,
                api.PHYSICAL_NETWORK: None,
                api.SEGMENTATION_ID: alloc.vxlan_vni}

    def release_segment(self, session, segment):
        vxlan_vni = segment[api.SEGMENTATION_ID]

        inside = any(lo <= vxlan_vni <= hi for lo, hi in self.vxlan_vni_ranges)

        with session.begin(subtransactions=True):
            query = (session.query(VxlanAllocation).
                     filter_by(vxlan_vni=vxlan_vni))
            if inside:
                count = query.update({"allocated": False})
                if count:
                    LOG.debug("Releasing vxlan tunnel %s to pool",
                              vxlan_vni)
            else:
                count = query.delete()
                if count:
                    LOG.debug("Releasing vxlan tunnel %s outside pool",
                              vxlan_vni)

        if not count:
            LOG.warning(_("vxlan_vni %s not found"), vxlan_vni)

    def _sync_vxlan_allocations(self):
        """
        Synchronize vxlan_allocations table with configured tunnel ranges.
        """

        # determine current configured allocatable vnis
        vxlan_vnis = set()
        for tun_min, tun_max in self.vxlan_vni_ranges:
            if tun_max + 1 - tun_min > MAX_VXLAN_VNI:
                LOG.error(_("Skipping unreasonable VXLAN VNI range "
                            "%(tun_min)s:%(tun_max)s"),
                          {'tun_min': tun_min, 'tun_max': tun_max})
            else:
                vxlan_vnis |= set(xrange(tun_min, tun_max + 1))

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

    def get_vxlan_allocation(self, session, vxlan_vni):
        with session.begin(subtransactions=True):
            return session.query(VxlanAllocation).filter_by(
                vxlan_vni=vxlan_vni).first()

    def get_endpoints(self):
        """Get every vxlan endpoints from database."""

        LOG.debug(_("get_vxlan_endpoints() called"))
        session = db_api.get_session()

        with session.begin(subtransactions=True):
            vxlan_endpoints = session.query(VxlanEndpoints)
            return [{'ip_address': vxlan_endpoint.ip_address,
                     'udp_port': vxlan_endpoint.udp_port}
                    for vxlan_endpoint in vxlan_endpoints]

    def add_endpoint(self, ip, udp_port=VXLAN_UDP_PORT):
        LOG.debug(_("add_vxlan_endpoint() called for ip %s"), ip)
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            try:
                vxlan_endpoint = (session.query(VxlanEndpoints).
                                  filter_by(ip_address=ip).
                                  with_lockmode('update').one())
            except sa_exc.NoResultFound:
                vxlan_endpoint = VxlanEndpoints(ip_address=ip,
                                                udp_port=udp_port)
                session.add(vxlan_endpoint)
            return vxlan_endpoint

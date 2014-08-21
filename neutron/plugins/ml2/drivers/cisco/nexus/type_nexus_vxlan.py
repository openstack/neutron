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
#
#    Author: Arvind Somya (asomya@cisco.com)

import netaddr
import sys

from oslo.config import cfg
from six import moves
import sqlalchemy as sa

from neutron.common import constants as q_const
from neutron.common import exceptions as exc
from neutron.common import utils
from neutron.db import api as db_api
from neutron.db import model_base
from neutron.db import models_v2
from neutron.openstack.common import log
from neutron.plugins.common import constants as p_const
from neutron.plugins.common import utils as plugin_utils
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import helpers
from neutron.plugins.ml2.drivers import type_tunnel

LOG = log.getLogger(__name__)

MAX_VXLAN_VNI = 16777215

nexus_vxlan_opts = [
    cfg.ListOpt('vni_ranges',
                default=[],
                help=_("List of global VNID ranges in the format - a:b, c:d."
                       "Multiple ranges can be separated by a comma")),
    cfg.ListOpt('mcast_ranges',
                default=[],
                help=_("List of multicast groups to be used for global VNIDs"
                       "in the format - a:b,c,e:f."))
]

cfg.CONF.register_opts(nexus_vxlan_opts, "ml2_type_nexus_vxlan")


class NexusVxlanAllocation(model_base.BASEV2):

    __tablename__ = 'ml2_nexus_vxlan_allocations'

    vxlan_vni = sa.Column(sa.Integer, nullable=False, primary_key=True,
                          autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False,
                          server_default=sa.sql.false())


class NexusMcastGroup(model_base.BASEV2, models_v2.HasId):

    __tablename__ = 'ml2_nexus_vxlan_mcast_groups'

    mcast_group = sa.Column(sa.String(64), nullable=False)
    associated_vni = sa.Column(sa.Integer,
                               sa.ForeignKey('ml2_nexus_vxlan_allocations.vxlan_vni',
                                             ondelete="CASCADE"),
                               nullable=False)


class NexusVxlanTypeDriver(helpers.TypeDriverHelper,
                           type_tunnel.TunnelTypeDriver):

    def __init__(self):
        super(NexusVxlanTypeDriver, self).__init__(NexusVxlanAllocation)

    def _get_mcast_group_for_vni(self, session, vni):
        mcast_grp = (session.query(NexusMcastGroup).
                     filter_by(associated_vni=vni).first())
        if not mcast_grp:
            mcast_grp = self._allocate_mcast_group(session, vni)
        return mcast_grp

    def get_type(self):
        return p_const.TYPE_NEXUS_VXLAN

    def initialize(self):
        self.vxlan_vni_ranges = []
        self._parse_tunnel_ranges(
            cfg.CONF.ml2_type_nexus_vxlan.vni_ranges,
            self.vxlan_vni_ranges,
            p_const.TYPE_NEXUS_VXLAN
        )
        self._sync_vxlan_allocations()
        self.conf_mcast_ranges = cfg.CONF.ml2_type_nexus_vxlan.mcast_ranges
        self.conf_vxlan_ranges = cfg.CONF.ml2_type_nexus_vxlan.vni_ranges

    def _parse_mcast_ranges(self):
        ranges = (range.split(':') for range in self.conf_mcast_ranges)
        for low, high in ranges:
            for mcast_ip in netaddr.iter_iprange(low, high):
                if mcast_ip.is_multicast():
                    yield mcast_ip

    def _allocate_mcast_group(self, session, vni):
        allocs = dict(session.query(NexusMcastGroup.mcast_group,
                      sa.func.count(NexusMcastGroup.mcast_group)).
                      group_by(NexusMcastGroup.mcast_group).all())

        mcast_for_vni = None
        for mcast_ip in self._parse_mcast_ranges():
            if not unicode(mcast_ip) in allocs:
                mcast_for_vni = mcast_ip
                break

        if not mcast_for_vni:
            mcast_for_vni = min(allocs, key=allocs.get)

        alloc = NexusMcastGroup(mcast_group=mcast_for_vni,
                                associated_vni=vni)

        session.add(alloc)
        session.flush()
        return mcast_for_vni

    def _parse_vxlan_ranges(self):
        ranges = (range.split() for range in split(',', conf_vxlan_ranges))
        for low,high in ranges:
            for vni in range(low,high):
                yield vni

    def allocate_tenant_segment(self, session):
        alloc = self.allocate_partially_specified_segment(session)
        if not alloc:
            return
        vni = alloc.vxlan_vni
        mcast_group = self._get_mcast_group_for_vni(session, vni)
        return {api.NETWORK_TYPE: p_const.TYPE_NEXUS_VXLAN,
                api.PHYSICAL_NETWORK: mcast_group,
                api.SEGMENTATION_ID: alloc.vxlan_vni}

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
            allocs = (session.query(NexusVxlanAllocation).
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
                session.query(NexusVxlanAllocation).filter(
                    NexusVxlanAllocation.vxlan_vni.in_(vni_list)).delete(
                        synchronize_session=False)
            # collect vnis that need to be added
            vnis = list(vxlan_vnis - existing_vnis)
            chunked_vnis = (vnis[i:i + bulk_size] for i in
                            range(0, len(vnis), bulk_size))
            for vni_list in chunked_vnis:
                bulk = [{'vxlan_vni': vni, 'allocated': False}
                        for vni in vni_list]
                session.execute(NexusVxlanAllocation.__table__.insert(), bulk)

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

    def release_segment(self, session, segment):
        vxlan_vni = segment[api.SEGMENTATION_ID]

        inside = any(lo <= vxlan_vni <= hi for lo, hi in self.vxlan_vni_ranges)

        with session.begin(subtransactions=True):
            query = (session.query(NexusVxlanAllocation).
                     filter_by(vxlan_vni=vxlan_vni))
            if inside:
                count = query.update({"allocated": False})
                if count:
                    mcast_row = (session.query(NexusMcastGroup).
                                 filter_by(associated_vni=vxlan_vni).first())
                    session.delete(mcast_row)
                    LOG.debug("Releasing vxlan tunnel %s to pool",
                              vxlan_vni)
            else:
                count = query.delete()
                if count:
                    LOG.debug("Releasing vxlan tunnel %s outside pool",
                              vxlan_vni)

        if not count:
            LOG.warning(_("vxlan_vni %s not found"), vxlan_vni)

    def add_endpoint(self, ip, udp_port):
        pass

    def get_endpoints(self):
        pass

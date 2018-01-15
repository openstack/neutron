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

import sys

from neutron_lib import constants as p_const
from neutron_lib import context
from neutron_lib import exceptions as exc
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg
from oslo_log import log
from six import moves

from neutron._i18n import _
from neutron.conf.plugins.ml2.drivers import driver_type
from neutron.db import api as db_api
from neutron.objects.plugins.ml2 import vlanallocation as vlanalloc
from neutron.plugins.common import utils as plugin_utils
from neutron.plugins.ml2.drivers import helpers

LOG = log.getLogger(__name__)

driver_type.register_ml2_drivers_vlan_opts()


class VlanTypeDriver(helpers.SegmentTypeDriver):
    """Manage state for VLAN networks with ML2.

    The VlanTypeDriver implements the 'vlan' network_type. VLAN
    network segments provide connectivity between VMs and other
    devices using any connected IEEE 802.1Q conformant
    physical_network segmented into virtual networks via IEEE 802.1Q
    headers. Up to 4094 VLAN network segments can exist on each
    available physical_network.
    """

    def __init__(self):
        super(VlanTypeDriver, self).__init__(vlanalloc.VlanAllocation)
        self._parse_network_vlan_ranges()

    def _parse_network_vlan_ranges(self):
        try:
            self.network_vlan_ranges = plugin_utils.parse_network_vlan_ranges(
                cfg.CONF.ml2_type_vlan.network_vlan_ranges)
        except Exception:
            LOG.exception("Failed to parse network_vlan_ranges. "
                          "Service terminated!")
            sys.exit(1)
        LOG.info("Network VLAN ranges: %s", self.network_vlan_ranges)

    @db_api.retry_db_errors
    def _sync_vlan_allocations(self):
        ctx = context.get_admin_context()
        with db_api.context_manager.writer.using(ctx):
            # get existing allocations for all physical networks
            allocations = dict()
            allocs = vlanalloc.VlanAllocation.get_objects(ctx)
            for alloc in allocs:
                if alloc.physical_network not in allocations:
                    allocations[alloc.physical_network] = list()
                allocations[alloc.physical_network].append(alloc)

            # process vlan ranges for each configured physical network
            for (physical_network,
                 vlan_ranges) in self.network_vlan_ranges.items():
                # determine current configured allocatable vlans for
                # this physical network
                vlan_ids = set()
                for vlan_min, vlan_max in vlan_ranges:
                    vlan_ids |= set(moves.range(vlan_min, vlan_max + 1))

                # remove from table unallocated vlans not currently
                # allocatable
                if physical_network in allocations:
                    for alloc in allocations[physical_network]:
                        try:
                            # see if vlan is allocatable
                            vlan_ids.remove(alloc.vlan_id)
                        except KeyError:
                            # it's not allocatable, so check if its allocated
                            if not alloc.allocated:
                                # it's not, so remove it from table
                                LOG.debug("Removing vlan %(vlan_id)s on "
                                          "physical network "
                                          "%(physical_network)s from pool",
                                          {'vlan_id': alloc.vlan_id,
                                           'physical_network':
                                           physical_network})
                                # This UPDATE WHERE statement blocks anyone
                                # from concurrently changing the allocation
                                # values to True while our transaction is
                                # open so we don't accidentally delete
                                # allocated segments. If someone has already
                                # allocated, update_objects will return 0 so we
                                # don't delete.
                                if vlanalloc.VlanAllocation.update_objects(
                                    ctx, values={'allocated': False},
                                    allocated=False, vlan_id=alloc.vlan_id,
                                    physical_network=physical_network):
                                    alloc.delete()
                    del allocations[physical_network]

                # add missing allocatable vlans to table
                for vlan_id in sorted(vlan_ids):
                    alloc = vlanalloc.VlanAllocation(
                        ctx,
                        physical_network=physical_network,
                        vlan_id=vlan_id, allocated=False)
                    alloc.create()

            # remove from table unallocated vlans for any unconfigured
            # physical networks
            for allocs in allocations.values():
                for alloc in allocs:
                    if not alloc.allocated:
                        LOG.debug("Removing vlan %(vlan_id)s on physical "
                                  "network %(physical_network)s from pool",
                                  {'vlan_id': alloc.vlan_id,
                                   'physical_network':
                                   alloc.physical_network})
                        alloc.delete()

    def get_type(self):
        return p_const.TYPE_VLAN

    def initialize(self):
        self._sync_vlan_allocations()
        LOG.info("VlanTypeDriver initialization complete")

    def is_partial_segment(self, segment):
        return segment.get(api.SEGMENTATION_ID) is None

    def validate_provider_segment(self, segment):
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        segmentation_id = segment.get(api.SEGMENTATION_ID)
        if physical_network:
            if physical_network not in self.network_vlan_ranges:
                msg = (_("physical_network '%s' unknown "
                         "for VLAN provider network") % physical_network)
                raise exc.InvalidInput(error_message=msg)
            if segmentation_id:
                if not plugin_utils.is_valid_vlan_tag(segmentation_id):
                    msg = (_("segmentation_id out of range (%(min)s through "
                             "%(max)s)") %
                           {'min': p_const.MIN_VLAN_TAG,
                            'max': p_const.MAX_VLAN_TAG})
                    raise exc.InvalidInput(error_message=msg)
            else:
                if not self.network_vlan_ranges.get(physical_network):
                    msg = (_("Physical network %s requires segmentation_id "
                             "to be specified when creating a provider "
                             "network") % physical_network)
                    raise exc.InvalidInput(error_message=msg)
        elif segmentation_id:
            msg = _("segmentation_id requires physical_network for VLAN "
                    "provider network")
            raise exc.InvalidInput(error_message=msg)

        for key, value in segment.items():
            if value and key not in [api.NETWORK_TYPE,
                                     api.PHYSICAL_NETWORK,
                                     api.SEGMENTATION_ID]:
                msg = _("%s prohibited for VLAN provider network") % key
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, context, segment):
        filters = {}
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        if physical_network is not None:
            filters['physical_network'] = physical_network
            vlan_id = segment.get(api.SEGMENTATION_ID)
            if vlan_id is not None:
                filters['vlan_id'] = vlan_id

        if self.is_partial_segment(segment):
            alloc = self.allocate_partially_specified_segment(
                context, **filters)
            if not alloc:
                raise exc.NoNetworkAvailable()
        else:
            alloc = self.allocate_fully_specified_segment(
                context, **filters)
            if not alloc:
                raise exc.VlanIdInUse(**filters)

        return {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                api.PHYSICAL_NETWORK: alloc.physical_network,
                api.SEGMENTATION_ID: alloc.vlan_id,
                api.MTU: self.get_mtu(alloc.physical_network)}

    def allocate_tenant_segment(self, context):
        for physnet in self.network_vlan_ranges:
            alloc = self.allocate_partially_specified_segment(
                context, physical_network=physnet)
            if alloc:
                break
        else:
            return
        return {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                api.PHYSICAL_NETWORK: alloc.physical_network,
                api.SEGMENTATION_ID: alloc.vlan_id,
                api.MTU: self.get_mtu(alloc.physical_network)}

    def release_segment(self, context, segment):
        physical_network = segment[api.PHYSICAL_NETWORK]
        vlan_id = segment[api.SEGMENTATION_ID]

        ranges = self.network_vlan_ranges.get(physical_network, [])
        inside = any(lo <= vlan_id <= hi for lo, hi in ranges)
        count = False

        with db_api.context_manager.writer.using(context):
            alloc = vlanalloc.VlanAllocation.get_object(
                context, physical_network=physical_network, vlan_id=vlan_id)
            if alloc:
                if inside and alloc.allocated:
                    count = True
                    alloc.allocated = False
                    alloc.update()
                    LOG.debug("Releasing vlan %(vlan_id)s on physical "
                              "network %(physical_network)s to pool",
                              {'vlan_id': vlan_id,
                               'physical_network': physical_network})
                else:
                    count = True
                    alloc.delete()
                    LOG.debug("Releasing vlan %(vlan_id)s on physical "
                              "network %(physical_network)s outside pool",
                              {'vlan_id': vlan_id,
                               'physical_network': physical_network})

        if not count:
            LOG.warning("No vlan_id %(vlan_id)s found on physical "
                        "network %(physical_network)s",
                        {'vlan_id': vlan_id,
                         'physical_network': physical_network})

    def get_mtu(self, physical_network):
        seg_mtu = super(VlanTypeDriver, self).get_mtu()
        mtu = []
        if seg_mtu > 0:
            mtu.append(seg_mtu)
        if physical_network in self.physnet_mtus:
            mtu.append(int(self.physnet_mtus[physical_network]))
        return min(mtu) if mtu else 0

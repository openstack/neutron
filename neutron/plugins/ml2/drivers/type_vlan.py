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

import collections
import sys

from neutron_lib import constants as p_const
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as exc
from neutron_lib.objects import exceptions as o_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api
from neutron_lib.plugins import utils as plugin_utils
from oslo_config import cfg
from oslo_log import log

from neutron._i18n import _
from neutron.conf.plugins.ml2.drivers import driver_type
from neutron.db.models.plugins.ml2 import vlanallocation as vlan_alloc_model
from neutron.objects import network_segment_range as range_obj
from neutron.objects.plugins.ml2 import vlanallocation as vlanalloc
from neutron.plugins.ml2.drivers import helpers
from neutron.services.network_segment_range import plugin as range_plugin

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
        super().__init__(vlanalloc.VlanAllocation)
        self.model_segmentation_id = vlan_alloc_model.VlanAllocation.vlan_id
        self._parse_network_vlan_ranges()

    def _populate_new_default_network_segment_ranges(self, ctx, start_time):
        for (physical_network, vlan_ranges) in (
                self._network_vlan_ranges.items()):
            for vlan_min, vlan_max in vlan_ranges:
                range_obj.NetworkSegmentRange.new_default(
                    ctx, self.get_type(), physical_network, vlan_min,
                    vlan_max, start_time)

    def _parse_network_vlan_ranges(self):
        try:
            self._network_vlan_ranges = plugin_utils.parse_network_vlan_ranges(
                cfg.CONF.ml2_type_vlan.network_vlan_ranges)
        except Exception:
            LOG.exception("Failed to parse network_vlan_ranges. "
                          "Service terminated!")
            sys.exit(1)
        LOG.info("Network VLAN ranges: %s", self._network_vlan_ranges)

    @db_api.retry_db_errors
    def _sync_vlan_allocations(self, ctx=None):
        ctx = ctx or context.get_admin_context()
        with db_api.CONTEXT_WRITER.using(ctx):
            # VLAN ranges per physical network:
            #   {phy1: [(1, 10), (30, 50)], ...}
            ranges = self.get_network_segment_ranges()

            # Delete those VLAN registers from unconfigured physical networks
            physnets = vlanalloc.VlanAllocation.get_physical_networks(ctx)
            physnets_unconfigured = physnets - set(ranges)
            if physnets_unconfigured:
                LOG.debug('Removing any VLAN register on physical networks %s',
                          physnets_unconfigured)
                vlanalloc.VlanAllocation.delete_physical_networks(
                    ctx, physnets_unconfigured)

            # Get existing allocations for all configured physical networks
            allocations = collections.defaultdict(list)
            for alloc in vlanalloc.VlanAllocation.get_objects(ctx):
                allocations[alloc.physical_network].append(alloc)

            for physical_network, vlan_ranges in ranges.items():
                # determine current configured allocatable vlans for
                # this physical network
                vlan_ids = set()
                for vlan_min, vlan_max in vlan_ranges:
                    vlan_ids |= set(range(vlan_min, vlan_max + 1))

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

                # Add missing allocatable VLAN registers for "physical_network"
                vlanalloc.VlanAllocation.bulk_create(ctx, physical_network,
                                                     vlan_ids)

    @db_api.retry_db_errors
    def _get_network_segment_ranges_from_db(self, ctx=None):
        ranges = {}
        ctx = ctx or context.get_admin_context()
        with db_api.CONTEXT_READER.using(ctx):
            range_objs = (range_obj.NetworkSegmentRange.get_objects(
                ctx, network_type=self.get_type()))
            for obj in range_objs:
                physical_network = obj['physical_network']
                if physical_network not in ranges:
                    ranges[physical_network] = []
                ranges[physical_network].append((obj['minimum'],
                                                 obj['maximum']))
        return ranges

    def get_type(self):
        return p_const.TYPE_VLAN

    def initialize(self):
        if not range_plugin.is_network_segment_range_enabled():
            # service plugins are initialized/loaded after the ML2 driver
            # initialization. Thus, we base on the information whether
            # ``network_segment_range`` service plugin is enabled/defined in
            # ``neutron.conf`` to decide whether to skip the first time sync
            # allocation during driver initialization, instead of using the
            # directory.get_plugin() method - the normal way used elsewhere to
            # check if a plugin is loaded.
            self._sync_vlan_allocations()
        LOG.info("VlanTypeDriver initialization complete")

    @db_api.retry_db_errors
    def initialize_network_segment_range_support(self, start_time):
        admin_context = context.get_admin_context()
        try:
            with db_api.CONTEXT_WRITER.using(admin_context):
                self._delete_expired_default_network_segment_ranges(
                    admin_context, start_time)
                self._populate_new_default_network_segment_ranges(
                    admin_context, start_time)
        except o_exc.NeutronDbObjectDuplicateEntry:
            pass

        # Override self._network_vlan_ranges with the network segment range
        # information from DB and then do a sync_allocations since the
        # segment range service plugin has not yet been loaded at this
        # initialization time.
        self._network_vlan_ranges = (
            self._get_network_segment_ranges_from_db(ctx=admin_context))
        self._sync_vlan_allocations(ctx=admin_context)

    def update_network_segment_range_allocations(self):
        self._sync_vlan_allocations()

    def get_network_segment_ranges(self):
        """Get the driver network segment ranges.

        Queries all VLAN network segment ranges from DB if the
        ``NETWORK_SEGMENT_RANGE`` service plugin is enabled. Otherwise,
        they will be loaded from the host config file - `ml2_conf.ini`.
        """
        ranges = self._network_vlan_ranges
        if directory.get_plugin(plugin_constants.NETWORK_SEGMENT_RANGE):
            ranges = self._get_network_segment_ranges_from_db()

        return ranges

    def is_partial_segment(self, segment):
        return segment.get(api.SEGMENTATION_ID) is None

    def validate_provider_segment(self, segment):
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        segmentation_id = segment.get(api.SEGMENTATION_ID)
        ranges = self.get_network_segment_ranges()
        if physical_network:
            if physical_network not in ranges:
                msg = (_("physical_network '%s' unknown "
                         "for VLAN provider network") % physical_network)
                raise exc.InvalidInput(error_message=msg)
            if segmentation_id is not None:
                if not plugin_utils.is_valid_vlan_tag(segmentation_id):
                    msg = (_("segmentation_id out of range (%(min)s through "
                             "%(max)s)") %
                           {'min': p_const.MIN_VLAN_TAG,
                            'max': p_const.MAX_VLAN_TAG})
                    raise exc.InvalidInput(error_message=msg)
        elif segmentation_id is not None:
            msg = _("segmentation_id requires physical_network for VLAN "
                    "provider network")
            raise exc.InvalidInput(error_message=msg)

        for key, value in segment.items():
            if value and key not in [api.NETWORK_TYPE,
                                     api.PHYSICAL_NETWORK,
                                     api.SEGMENTATION_ID]:
                msg = _("%s prohibited for VLAN provider network") % key
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, context, segment, filters=None):
        filters = filters or {}
        project_id = filters.get('project_id')
        filters = {}
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        if physical_network is not None:
            filters['physical_network'] = physical_network
            vlan_id = segment.get(api.SEGMENTATION_ID)
            if vlan_id is not None:
                filters['vlan_id'] = vlan_id

        if self.is_partial_segment(segment):
            if (directory.get_plugin(
                    plugin_constants.NETWORK_SEGMENT_RANGE) and project_id):
                filters['project_id'] = project_id
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

    def allocate_tenant_segment(self, context, filters=None):
        filters = filters or {}
        ranges = self.get_network_segment_ranges()
        for physnet in ranges:
            filters['physical_network'] = physnet
            alloc = self.allocate_partially_specified_segment(
                context, **filters)
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

        vlan_ranges = self.get_network_segment_ranges()
        ranges = vlan_ranges.get(physical_network, [])
        inside = any(lo <= vlan_id <= hi for lo, hi in ranges)
        count = False

        with db_api.CONTEXT_WRITER.using(context):
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
        seg_mtu = super().get_mtu()
        mtu = []
        if seg_mtu > 0:
            mtu.append(seg_mtu)
        if physical_network in self.physnet_mtus:
            mtu.append(int(self.physnet_mtus[physical_network]))
        return min(mtu) if mtu else 0

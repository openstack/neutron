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

from neutron_lib import constants as p_const
from neutron_lib import exceptions as exc
from neutron_lib.objects import exceptions as obj_base
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg
from oslo_log import log

from neutron._i18n import _
from neutron.common import exceptions as n_exc
from neutron.conf.plugins.ml2.drivers import driver_type
from neutron.db import api as db_api
from neutron.objects.plugins.ml2 import flatallocation as flat_obj
from neutron.plugins.ml2.drivers import helpers

LOG = log.getLogger(__name__)

driver_type.register_ml2_drivers_flat_opts()


class FlatTypeDriver(helpers.BaseTypeDriver):
    """Manage state for flat networks with ML2.

    The FlatTypeDriver implements the 'flat' network_type. Flat
    network segments provide connectivity between VMs and other
    devices using any connected IEEE 802.1D conformant
    physical_network, without the use of VLAN tags, tunneling, or
    other segmentation mechanisms. Therefore at most one flat network
    segment can exist on each available physical_network.
    """

    def __init__(self):
        super(FlatTypeDriver, self).__init__()
        self._parse_networks(cfg.CONF.ml2_type_flat.flat_networks)

    def _parse_networks(self, entries):
        self.flat_networks = entries
        if '*' in self.flat_networks:
            LOG.info("Arbitrary flat physical_network names allowed")
            self.flat_networks = None
        elif not self.flat_networks:
            LOG.info("Flat networks are disabled")
        else:
            LOG.info("Allowable flat physical_network names: %s",
                     self.flat_networks)

    def get_type(self):
        return p_const.TYPE_FLAT

    def initialize(self):
        LOG.info("ML2 FlatTypeDriver initialization complete")

    def is_partial_segment(self, segment):
        return False

    def validate_provider_segment(self, segment):
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        if not physical_network:
            msg = _("physical_network required for flat provider network")
            raise exc.InvalidInput(error_message=msg)
        if self.flat_networks is not None and not self.flat_networks:
            msg = _("Flat provider networks are disabled")
            raise exc.InvalidInput(error_message=msg)
        if self.flat_networks and physical_network not in self.flat_networks:
            msg = (_("physical_network '%s' unknown for flat provider network")
                   % physical_network)
            raise exc.InvalidInput(error_message=msg)

        for key, value in segment.items():
            if value and key not in [api.NETWORK_TYPE,
                                     api.PHYSICAL_NETWORK]:
                msg = _("%s prohibited for flat provider network") % key
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, context, segment):
        physical_network = segment[api.PHYSICAL_NETWORK]
        try:
            LOG.debug("Reserving flat network on physical "
                      "network %s", physical_network)
            alloc = flat_obj.FlatAllocation(
                context,
                physical_network=physical_network)
            alloc.create()
        except obj_base.NeutronDbObjectDuplicateEntry:
            raise n_exc.FlatNetworkInUse(
                physical_network=physical_network)
        segment[api.MTU] = self.get_mtu(alloc.physical_network)
        return segment

    def allocate_tenant_segment(self, context):
        # Tenant flat networks are not supported.
        return

    def release_segment(self, context, segment):
        physical_network = segment[api.PHYSICAL_NETWORK]
        with db_api.context_manager.writer.using(context):
            obj = flat_obj.FlatAllocation.get_object(
                context,
                physical_network=physical_network)
            if obj:
                obj.delete()
                LOG.debug("Releasing flat network on physical network %s",
                          physical_network)
            else:
                LOG.warning(
                    "No flat network found on physical network %s",
                    physical_network)

    def get_mtu(self, physical_network):
        seg_mtu = super(FlatTypeDriver, self).get_mtu()
        mtu = []
        if seg_mtu > 0:
            mtu.append(seg_mtu)
        if physical_network in self.physnet_mtus:
            mtu.append(int(self.physnet_mtus[physical_network]))
        return min(mtu) if mtu else 0

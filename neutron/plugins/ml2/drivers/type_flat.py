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
import six
import sqlalchemy as sa

from neutron.common import exceptions as exc
from neutron.db import model_base
from neutron.i18n import _LI, _LW
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import helpers

LOG = log.getLogger(__name__)

flat_opts = [
    cfg.ListOpt('flat_networks',
                default=[],
                help=_("List of physical_network names with which flat "
                       "networks can be created. Use * to allow flat "
                       "networks with arbitrary physical_network names."))
]

cfg.CONF.register_opts(flat_opts, "ml2_type_flat")


class FlatAllocation(model_base.BASEV2):
    """Represent persistent allocation state of a physical network.

    If a record exists for a physical network, then that physical
    network has been allocated as a flat network.
    """

    __tablename__ = 'ml2_flat_allocations'

    physical_network = sa.Column(sa.String(64), nullable=False,
                                 primary_key=True)


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
            LOG.info(_LI("Arbitrary flat physical_network names allowed"))
            self.flat_networks = None
        elif not all(self.flat_networks):
            msg = _("physical network name is empty")
            raise exc.InvalidInput(error_message=msg)
        else:
            LOG.info(_LI("Allowable flat physical_network names: %s"),
                     self.flat_networks)

    def get_type(self):
        return p_const.TYPE_FLAT

    def initialize(self):
        LOG.info(_LI("ML2 FlatTypeDriver initialization complete"))

    def is_partial_segment(self, segment):
        return False

    def validate_provider_segment(self, segment):
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        if not physical_network:
            msg = _("physical_network required for flat provider network")
            raise exc.InvalidInput(error_message=msg)
        if self.flat_networks and physical_network not in self.flat_networks:
            msg = (_("physical_network '%s' unknown for flat provider network")
                   % physical_network)
            raise exc.InvalidInput(error_message=msg)

        for key, value in six.iteritems(segment):
            if value and key not in [api.NETWORK_TYPE,
                                     api.PHYSICAL_NETWORK]:
                msg = _("%s prohibited for flat provider network") % key
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, session, segment):
        physical_network = segment[api.PHYSICAL_NETWORK]
        with session.begin(subtransactions=True):
            try:
                LOG.debug("Reserving flat network on physical "
                          "network %s", physical_network)
                alloc = FlatAllocation(physical_network=physical_network)
                alloc.save(session)
            except db_exc.DBDuplicateEntry:
                raise exc.FlatNetworkInUse(
                    physical_network=physical_network)
            segment[api.MTU] = self.get_mtu(alloc.physical_network)
        return segment

    def allocate_tenant_segment(self, session):
        # Tenant flat networks are not supported.
        return

    def release_segment(self, session, segment):
        physical_network = segment[api.PHYSICAL_NETWORK]
        with session.begin(subtransactions=True):
            count = (session.query(FlatAllocation).
                     filter_by(physical_network=physical_network).
                     delete())
        if count:
            LOG.debug("Releasing flat network on physical network %s",
                      physical_network)
        else:
            LOG.warning(_LW("No flat network found on physical network %s"),
                        physical_network)

    def get_mtu(self, physical_network):
        seg_mtu = super(FlatTypeDriver, self).get_mtu()
        mtu = []
        if seg_mtu > 0:
            mtu.append(seg_mtu)
        if physical_network in self.physnet_mtus:
            mtu.append(int(self.physnet_mtus[physical_network]))
        return min(mtu) if mtu else 0

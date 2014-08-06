# Copyright 2013 Cloudbase Solutions SRL
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

from six import moves
from sqlalchemy.orm import exc

from neutron.common import exceptions as n_exc
import neutron.db.api as db_api
from neutron.db import models_v2
from neutron.openstack.common import log as logging
from neutron.plugins.hyperv.common import constants
from neutron.plugins.hyperv import model as hyperv_model

LOG = logging.getLogger(__name__)


class HyperVPluginDB(object):

    def reserve_vlan(self, session):
        with session.begin(subtransactions=True):
            alloc_q = session.query(hyperv_model.VlanAllocation)
            alloc_q = alloc_q.filter_by(allocated=False)
            alloc = alloc_q.first()
            if alloc:
                LOG.debug(_("Reserving vlan %(vlan_id)s on physical network "
                            "%(physical_network)s from pool"),
                          {'vlan_id': alloc.vlan_id,
                           'physical_network': alloc.physical_network})
                alloc.allocated = True
                return (alloc.physical_network, alloc.vlan_id)
        raise n_exc.NoNetworkAvailable()

    def reserve_flat_net(self, session):
        with session.begin(subtransactions=True):
            alloc_q = session.query(hyperv_model.VlanAllocation)
            alloc_q = alloc_q.filter_by(allocated=False,
                                        vlan_id=constants.FLAT_VLAN_ID)
            alloc = alloc_q.first()
            if alloc:
                LOG.debug(_("Reserving flat physical network "
                            "%(physical_network)s from pool"),
                          {'physical_network': alloc.physical_network})
                alloc.allocated = True
                return alloc.physical_network
        raise n_exc.NoNetworkAvailable()

    def reserve_specific_vlan(self, session, physical_network, vlan_id):
        with session.begin(subtransactions=True):
            try:
                alloc_q = session.query(hyperv_model.VlanAllocation)
                alloc_q = alloc_q.filter_by(
                    physical_network=physical_network,
                    vlan_id=vlan_id)
                alloc = alloc_q.one()
                if alloc.allocated:
                    if vlan_id == constants.FLAT_VLAN_ID:
                        raise n_exc.FlatNetworkInUse(
                            physical_network=physical_network)
                    else:
                        raise n_exc.VlanIdInUse(
                            vlan_id=vlan_id,
                            physical_network=physical_network)
                LOG.debug(_("Reserving specific vlan %(vlan_id)s on physical "
                            "network %(physical_network)s from pool"),
                          {'vlan_id': vlan_id,
                           'physical_network': physical_network})
                alloc.allocated = True
            except exc.NoResultFound:
                raise n_exc.NoNetworkAvailable()

    def reserve_specific_flat_net(self, session, physical_network):
        return self.reserve_specific_vlan(session, physical_network,
                                          constants.FLAT_VLAN_ID)

    def add_network_binding(self, session, network_id, network_type,
                            physical_network, segmentation_id):
        with session.begin(subtransactions=True):
            binding = hyperv_model.NetworkBinding(
                network_id, network_type,
                physical_network,
                segmentation_id)
            session.add(binding)

    def get_port(self, port_id):
        session = db_api.get_session()
        try:
            port = session.query(models_v2.Port).filter_by(id=port_id).one()
        except exc.NoResultFound:
            port = None
        return port

    def get_network_binding(self, session, network_id):
        session = session or db_api.get_session()
        try:
            binding_q = session.query(hyperv_model.NetworkBinding)
            binding_q = binding_q.filter_by(network_id=network_id)
            return binding_q.one()
        except exc.NoResultFound:
            return

    def set_port_status(self, port_id, status):
        session = db_api.get_session()
        try:
            port = session.query(models_v2.Port).filter_by(id=port_id).one()
            port['status'] = status
            session.merge(port)
            session.flush()
        except exc.NoResultFound:
            raise n_exc.PortNotFound(port_id=port_id)

    def release_vlan(self, session, physical_network, vlan_id):
        with session.begin(subtransactions=True):
            try:
                alloc_q = session.query(hyperv_model.VlanAllocation)
                alloc_q = alloc_q.filter_by(physical_network=physical_network,
                                            vlan_id=vlan_id)
                alloc = alloc_q.one()
                alloc.allocated = False
                #session.delete(alloc)
                LOG.debug(_("Releasing vlan %(vlan_id)s on physical network "
                            "%(physical_network)s"),
                          {'vlan_id': vlan_id,
                           'physical_network': physical_network})
            except exc.NoResultFound:
                LOG.warning(_("vlan_id %(vlan_id)s on physical network "
                              "%(physical_network)s not found"),
                            {'vlan_id': vlan_id,
                             'physical_network': physical_network})

    def _add_missing_allocatable_vlans(self, session, vlan_ids,
                                       physical_network):
        for vlan_id in sorted(vlan_ids):
            alloc = hyperv_model.VlanAllocation(
                physical_network, vlan_id)
            session.add(alloc)

    def _remove_non_allocatable_vlans(self, session,
                                      physical_network,
                                      vlan_ids,
                                      allocations):
        if physical_network in allocations:
            for alloc in allocations[physical_network]:
                try:
                    # see if vlan is allocatable
                    vlan_ids.remove(alloc.vlan_id)
                except KeyError:
                    # it's not allocatable, so check if its allocated
                    if not alloc.allocated:
                        # it's not, so remove it from table
                        LOG.debug(_(
                            "Removing vlan %(vlan_id)s on "
                            "physical network "
                            "%(physical_network)s from pool"),
                            {'vlan_id': alloc.vlan_id,
                                'physical_network': physical_network})
                        session.delete(alloc)
            del allocations[physical_network]

    def _remove_unconfigured_vlans(self, session, allocations):
        for allocs in allocations.itervalues():
            for alloc in allocs:
                if not alloc.allocated:
                    LOG.debug(_("Removing vlan %(vlan_id)s on physical "
                                "network %(physical_network)s from pool"),
                              {'vlan_id': alloc.vlan_id,
                               'physical_network': alloc.physical_network})
                    session.delete(alloc)

    def sync_vlan_allocations(self, network_vlan_ranges):
        """Synchronize vlan_allocations table with configured VLAN ranges."""

        session = db_api.get_session()
        with session.begin():
            # get existing allocations for all physical networks
            allocations = dict()
            allocs_q = session.query(hyperv_model.VlanAllocation)
            for alloc in allocs_q:
                allocations.setdefault(alloc.physical_network,
                                       set()).add(alloc)

            # process vlan ranges for each configured physical network
            for physical_network, vlan_ranges in network_vlan_ranges.items():
                # determine current configured allocatable vlans for this
                # physical network
                vlan_ids = set()
                for vlan_range in vlan_ranges:
                    vlan_ids |= set(moves.xrange(vlan_range[0],
                                                 vlan_range[1] + 1))

                # remove from table unallocated vlans not currently allocatable
                self._remove_non_allocatable_vlans(session,
                                                   physical_network,
                                                   vlan_ids,
                                                   allocations)

                # add missing allocatable vlans to table
                self._add_missing_allocatable_vlans(session, vlan_ids,
                                                    physical_network)

            # remove from table unallocated vlans for any unconfigured physical
            # networks
            self._remove_unconfigured_vlans(session, allocations)

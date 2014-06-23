# Copyright 2013 Mellanox Technologies, Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from six import moves
from sqlalchemy.orm import exc

from neutron.common import exceptions as n_exc
import neutron.db.api as db
from neutron.db import models_v2
from neutron.db import securitygroups_db as sg_db
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.plugins.mlnx.common import config  # noqa
from neutron.plugins.mlnx.db import mlnx_models_v2

LOG = logging.getLogger(__name__)


def _remove_non_allocatable_vlans(session, allocations,
                                  physical_network, vlan_ids):
    if physical_network in allocations:
        for entry in allocations[physical_network]:
            try:
                # see if vlan is allocatable
                vlan_ids.remove(entry.segmentation_id)
            except KeyError:
                # it's not allocatable, so check if its allocated
                if not entry.allocated:
                    # it's not, so remove it from table
                    LOG.debug(_(
                        "Removing vlan %(seg_id)s on "
                        "physical network "
                        "%(net)s from pool"),
                        {'seg_id': entry.segmentation_id,
                         'net': physical_network})
                    session.delete(entry)
        del allocations[physical_network]


def _add_missing_allocatable_vlans(session, physical_network, vlan_ids):
    for vlan_id in sorted(vlan_ids):
        entry = mlnx_models_v2.SegmentationIdAllocation(physical_network,
                                                        vlan_id)
        session.add(entry)


def _remove_unconfigured_vlans(session, allocations):
    for entries in allocations.itervalues():
        for entry in entries:
            if not entry.allocated:
                LOG.debug(_("Removing vlan %(seg_id)s on physical "
                            "network %(net)s from pool"),
                          {'seg_id': entry.segmentation_id,
                           'net': entry.physical_network})
                session.delete(entry)


def sync_network_states(network_vlan_ranges):
    """Synchronize network_states table with current configured VLAN ranges."""

    session = db.get_session()
    with session.begin():
        # get existing allocations for all physical networks
        allocations = dict()
        entries = (session.query(mlnx_models_v2.SegmentationIdAllocation).
                   all())
        for entry in entries:
            allocations.setdefault(entry.physical_network, set()).add(entry)

        # process vlan ranges for each configured physical network
        for physical_network, vlan_ranges in network_vlan_ranges.iteritems():
            # determine current configured allocatable vlans for this
            # physical network
            vlan_ids = set()
            for vlan_range in vlan_ranges:
                vlan_ids |= set(moves.xrange(vlan_range[0], vlan_range[1] + 1))

            # remove from table unallocated vlans not currently allocatable
            _remove_non_allocatable_vlans(session, allocations,
                                          physical_network, vlan_ids)

            # add missing allocatable vlans to table
            _add_missing_allocatable_vlans(session, physical_network, vlan_ids)

        # remove from table unallocated vlans for any unconfigured physical
        # networks
        _remove_unconfigured_vlans(session, allocations)


def get_network_state(physical_network, segmentation_id):
    """Get entry of specified network."""
    session = db.get_session()
    qry = session.query(mlnx_models_v2.SegmentationIdAllocation)
    qry = qry.filter_by(physical_network=physical_network,
                        segmentation_id=segmentation_id)
    return qry.first()


def reserve_network(session):
    with session.begin(subtransactions=True):
        entry = (session.query(mlnx_models_v2.SegmentationIdAllocation).
                 filter_by(allocated=False).
                 with_lockmode('update').
                 first())
        if not entry:
            raise n_exc.NoNetworkAvailable()
        LOG.debug(_("Reserving vlan %(seg_id)s on physical network "
                    "%(net)s from pool"),
                  {'seg_id': entry.segmentation_id,
                   'net': entry.physical_network})
        entry.allocated = True
        return (entry.physical_network, entry.segmentation_id)


def reserve_specific_network(session, physical_network, segmentation_id):
    with session.begin(subtransactions=True):
        log_args = {'seg_id': segmentation_id, 'phy_net': physical_network}
        try:
            entry = (session.query(mlnx_models_v2.SegmentationIdAllocation).
                     filter_by(physical_network=physical_network,
                               segmentation_id=segmentation_id).
                     with_lockmode('update').one())
            if entry.allocated:
                raise n_exc.VlanIdInUse(vlan_id=segmentation_id,
                                        physical_network=physical_network)
            LOG.debug(_("Reserving specific vlan %(seg_id)s "
                        "on physical network %(phy_net)s from pool"),
                      log_args)
            entry.allocated = True
        except exc.NoResultFound:
            LOG.debug(_("Reserving specific vlan %(seg_id)s on "
                        "physical network %(phy_net)s outside pool"),
                      log_args)
            entry = mlnx_models_v2.SegmentationIdAllocation(physical_network,
                                                            segmentation_id)
            entry.allocated = True
            session.add(entry)


def release_network(session, physical_network,
                    segmentation_id, network_vlan_ranges):
    with session.begin(subtransactions=True):
        log_args = {'seg_id': segmentation_id, 'phy_net': physical_network}
        try:
            state = (session.query(mlnx_models_v2.SegmentationIdAllocation).
                     filter_by(physical_network=physical_network,
                               segmentation_id=segmentation_id).
                     with_lockmode('update').
                     one())
            state.allocated = False
            inside = False
            for vlan_range in network_vlan_ranges.get(physical_network, []):
                if (segmentation_id >= vlan_range[0] and
                    segmentation_id <= vlan_range[1]):
                    inside = True
                    break
            if inside:
                LOG.debug(_("Releasing vlan %(seg_id)s "
                            "on physical network "
                            "%(phy_net)s to pool"),
                          log_args)
            else:
                LOG.debug(_("Releasing vlan %(seg_id)s "
                            "on physical network "
                            "%(phy_net)s outside pool"),
                          log_args)
                session.delete(state)
        except exc.NoResultFound:
            LOG.warning(_("vlan_id %(seg_id)s on physical network "
                          "%(phy_net)s not found"),
                        log_args)


def add_network_binding(session, network_id, network_type,
                        physical_network, vlan_id):
    with session.begin(subtransactions=True):
        binding = mlnx_models_v2.NetworkBinding(network_id, network_type,
                                                physical_network, vlan_id)
        session.add(binding)


def get_network_binding(session, network_id):
    return (session.query(mlnx_models_v2.NetworkBinding).
            filter_by(network_id=network_id).first())


def add_port_profile_binding(session, port_id, vnic_type):
    with session.begin(subtransactions=True):
        binding = mlnx_models_v2.PortProfileBinding(port_id, vnic_type)
        session.add(binding)


def get_port_profile_binding(session, port_id):
    return (session.query(mlnx_models_v2.PortProfileBinding).
            filter_by(port_id=port_id).first())


def get_port_from_device(device):
    """Get port from database."""
    LOG.debug(_("get_port_from_device() called"))
    session = db.get_session()
    sg_binding_port = sg_db.SecurityGroupPortBinding.port_id

    query = session.query(models_v2.Port,
                          sg_db.SecurityGroupPortBinding.security_group_id)
    query = query.outerjoin(sg_db.SecurityGroupPortBinding,
                            models_v2.Port.id == sg_binding_port)
    query = query.filter(models_v2.Port.id.startswith(device))
    port_and_sgs = query.all()
    if not port_and_sgs:
        return
    port = port_and_sgs[0][0]
    plugin = manager.NeutronManager.get_plugin()
    port_dict = plugin._make_port_dict(port)
    port_dict['security_groups'] = [
        sg_id for port_in_db, sg_id in port_and_sgs if sg_id
    ]
    port_dict['security_group_rules'] = []
    port_dict['security_group_source_groups'] = []
    port_dict['fixed_ips'] = [ip['ip_address']
                              for ip in port['fixed_ips']]
    return port_dict


def get_port_from_device_mac(device_mac):
    """Get port from database."""
    LOG.debug(_("Get_port_from_device_mac() called"))
    session = db.get_session()
    qry = session.query(models_v2.Port).filter_by(mac_address=device_mac)
    return qry.first()


def set_port_status(port_id, status):
    """Set the port status."""
    LOG.debug(_("Set_port_status as %s called"), status)
    session = db.get_session()
    try:
        port = session.query(models_v2.Port).filter_by(id=port_id).one()
        port['status'] = status
        session.merge(port)
        session.flush()
    except exc.NoResultFound:
        raise n_exc.PortNotFound(port_id=port_id)

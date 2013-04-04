# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Nicira Networks, Inc.
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
# @author: Aaron Rosen, Nicira Networks, Inc.
# @author: Bob Kukura, Red Hat, Inc.

from sqlalchemy.orm import exc

from quantum.common import exceptions as q_exc
import quantum.db.api as db
from quantum.db import models_v2
from quantum.db import securitygroups_db as sg_db
from quantum.extensions import securitygroup as ext_sg
from quantum import manager
from quantum.openstack.common import log as logging
from quantum.plugins.openvswitch.common import constants
from quantum.plugins.openvswitch import ovs_models_v2

LOG = logging.getLogger(__name__)


def initialize():
    db.configure_db()


def get_network_binding(session, network_id):
    session = session or db.get_session()
    try:
        binding = (session.query(ovs_models_v2.NetworkBinding).
                   filter_by(network_id=network_id).
                   one())
        return binding
    except exc.NoResultFound:
        return


def add_network_binding(session, network_id, network_type,
                        physical_network, segmentation_id):
    with session.begin(subtransactions=True):
        binding = ovs_models_v2.NetworkBinding(network_id, network_type,
                                               physical_network,
                                               segmentation_id)
        session.add(binding)


def sync_vlan_allocations(network_vlan_ranges):
    """Synchronize vlan_allocations table with configured VLAN ranges"""

    session = db.get_session()
    with session.begin():
        # get existing allocations for all physical networks
        allocations = dict()
        allocs = (session.query(ovs_models_v2.VlanAllocation).
                  all())
        for alloc in allocs:
            if alloc.physical_network not in allocations:
                allocations[alloc.physical_network] = set()
            allocations[alloc.physical_network].add(alloc)

        # process vlan ranges for each configured physical network
        for physical_network, vlan_ranges in network_vlan_ranges.iteritems():
            # determine current configured allocatable vlans for this
            # physical network
            vlan_ids = set()
            for vlan_range in vlan_ranges:
                vlan_ids |= set(xrange(vlan_range[0], vlan_range[1] + 1))

            # remove from table unallocated vlans not currently allocatable
            if physical_network in allocations:
                for alloc in allocations[physical_network]:
                    try:
                        # see if vlan is allocatable
                        vlan_ids.remove(alloc.vlan_id)
                    except KeyError:
                        # it's not allocatable, so check if its allocated
                        if not alloc.allocated:
                            # it's not, so remove it from table
                            LOG.debug(_("Removing vlan %(vlan_id)s on "
                                        "physical network "
                                        "%(physical_network)s from pool"),
                                      {'vlan_id': alloc.vlan_id,
                                       'physical_network': physical_network})
                            session.delete(alloc)
                del allocations[physical_network]

            # add missing allocatable vlans to table
            for vlan_id in sorted(vlan_ids):
                alloc = ovs_models_v2.VlanAllocation(physical_network, vlan_id)
                session.add(alloc)

        # remove from table unallocated vlans for any unconfigured physical
        # networks
        for allocs in allocations.itervalues():
            for alloc in allocs:
                if not alloc.allocated:
                    LOG.debug(_("Removing vlan %(vlan_id)s on physical "
                                "network %(physical_network)s from pool"),
                              {'vlan_id': alloc.vlan_id,
                               'physical_network': alloc.physical_network})
                    session.delete(alloc)


def get_vlan_allocation(physical_network, vlan_id):
    session = db.get_session()
    try:
        alloc = (session.query(ovs_models_v2.VlanAllocation).
                 filter_by(physical_network=physical_network,
                           vlan_id=vlan_id).
                 one())
        return alloc
    except exc.NoResultFound:
        return


def reserve_vlan(session):
    with session.begin(subtransactions=True):
        alloc = (session.query(ovs_models_v2.VlanAllocation).
                 filter_by(allocated=False).
                 with_lockmode('update').
                 first())
        if alloc:
            LOG.debug(_("Reserving vlan %(vlan_id)s on physical network "
                        "%(physical_network)s from pool"),
                      {'vlan_id': alloc.vlan_id,
                       'physical_network': alloc.physical_network})
            alloc.allocated = True
            return (alloc.physical_network, alloc.vlan_id)
    raise q_exc.NoNetworkAvailable()


def reserve_specific_vlan(session, physical_network, vlan_id):
    with session.begin(subtransactions=True):
        try:
            alloc = (session.query(ovs_models_v2.VlanAllocation).
                     filter_by(physical_network=physical_network,
                               vlan_id=vlan_id).
                     with_lockmode('update').
                     one())
            if alloc.allocated:
                if vlan_id == constants.FLAT_VLAN_ID:
                    raise q_exc.FlatNetworkInUse(
                        physical_network=physical_network)
                else:
                    raise q_exc.VlanIdInUse(vlan_id=vlan_id,
                                            physical_network=physical_network)
            LOG.debug(_("Reserving specific vlan %(vlan_id)s on physical "
                        "network %(physical_network)s from pool"), locals())
            alloc.allocated = True
        except exc.NoResultFound:
            LOG.debug(_("Reserving specific vlan %(vlan_id)s on physical "
                        "network %(physical_network)s outside pool"),
                      locals())
            alloc = ovs_models_v2.VlanAllocation(physical_network, vlan_id)
            alloc.allocated = True
            session.add(alloc)


def release_vlan(session, physical_network, vlan_id, network_vlan_ranges):
    with session.begin(subtransactions=True):
        try:
            alloc = (session.query(ovs_models_v2.VlanAllocation).
                     filter_by(physical_network=physical_network,
                               vlan_id=vlan_id).
                     with_lockmode('update').
                     one())
            alloc.allocated = False
            inside = False
            for vlan_range in network_vlan_ranges.get(physical_network, []):
                if vlan_id >= vlan_range[0] and vlan_id <= vlan_range[1]:
                    inside = True
                    break
            if not inside:
                session.delete(alloc)
                LOG.debug(_("Releasing vlan %(vlan_id)s on physical network "
                            "%(physical_network)s outside pool"),
                          locals())
            else:
                LOG.debug(_("Releasing vlan %(vlan_id)s on physical network "
                            "%(physical_network)s to pool"),
                          locals())
        except exc.NoResultFound:
            LOG.warning(_("vlan_id %(vlan_id)s on physical network "
                          "%(physical_network)s not found"),
                        locals())


def sync_tunnel_allocations(tunnel_id_ranges):
    """Synchronize tunnel_allocations table with configured tunnel ranges"""

    # determine current configured allocatable tunnels
    tunnel_ids = set()
    for tunnel_id_range in tunnel_id_ranges:
        tun_min, tun_max = tunnel_id_range
        if tun_max + 1 - tun_min > 1000000:
            LOG.error(_("Skipping unreasonable tunnel ID range "
                        "%(tun_min)s:%(tun_max)s"),
                      locals())
        else:
            tunnel_ids |= set(xrange(tun_min, tun_max + 1))

    session = db.get_session()
    with session.begin():
        # remove from table unallocated tunnels not currently allocatable
        allocs = (session.query(ovs_models_v2.TunnelAllocation).
                  all())
        for alloc in allocs:
            try:
                # see if tunnel is allocatable
                tunnel_ids.remove(alloc.tunnel_id)
            except KeyError:
                # it's not allocatable, so check if its allocated
                if not alloc.allocated:
                    # it's not, so remove it from table
                    LOG.debug(_("Removing tunnel %s from pool"),
                              alloc.tunnel_id)
                    session.delete(alloc)

        # add missing allocatable tunnels to table
        for tunnel_id in sorted(tunnel_ids):
            alloc = ovs_models_v2.TunnelAllocation(tunnel_id)
            session.add(alloc)


def get_tunnel_allocation(tunnel_id):
    session = db.get_session()
    try:
        alloc = (session.query(ovs_models_v2.TunnelAllocation).
                 filter_by(tunnel_id=tunnel_id).
                 with_lockmode('update').
                 one())
        return alloc
    except exc.NoResultFound:
        return


def reserve_tunnel(session):
    with session.begin(subtransactions=True):
        alloc = (session.query(ovs_models_v2.TunnelAllocation).
                 filter_by(allocated=False).
                 with_lockmode('update').
                 first())
        if alloc:
            LOG.debug(_("Reserving tunnel %s from pool"), alloc.tunnel_id)
            alloc.allocated = True
            return alloc.tunnel_id
    raise q_exc.NoNetworkAvailable()


def reserve_specific_tunnel(session, tunnel_id):
    with session.begin(subtransactions=True):
        try:
            alloc = (session.query(ovs_models_v2.TunnelAllocation).
                     filter_by(tunnel_id=tunnel_id).
                     with_lockmode('update').
                     one())
            if alloc.allocated:
                raise q_exc.TunnelIdInUse(tunnel_id=tunnel_id)
            LOG.debug(_("Reserving specific tunnel %s from pool"), tunnel_id)
            alloc.allocated = True
        except exc.NoResultFound:
            LOG.debug(_("Reserving specific tunnel %s outside pool"),
                      tunnel_id)
            alloc = ovs_models_v2.TunnelAllocation(tunnel_id)
            alloc.allocated = True
            session.add(alloc)


def release_tunnel(session, tunnel_id, tunnel_id_ranges):
    with session.begin(subtransactions=True):
        try:
            alloc = (session.query(ovs_models_v2.TunnelAllocation).
                     filter_by(tunnel_id=tunnel_id).
                     with_lockmode('update').
                     one())
            alloc.allocated = False
            inside = False
            for tunnel_id_range in tunnel_id_ranges:
                if (tunnel_id >= tunnel_id_range[0]
                    and tunnel_id <= tunnel_id_range[1]):
                    inside = True
                    break
            if not inside:
                session.delete(alloc)
                LOG.debug(_("Releasing tunnel %s outside pool"), tunnel_id)
            else:
                LOG.debug(_("Releasing tunnel %s to pool"), tunnel_id)
        except exc.NoResultFound:
            LOG.warning(_("tunnel_id %s not found"), tunnel_id)


def get_port(port_id):
    session = db.get_session()
    try:
        port = session.query(models_v2.Port).filter_by(id=port_id).one()
    except exc.NoResultFound:
        port = None
    return port


def get_port_from_device(port_id):
    """Get port from database"""
    LOG.debug(_("get_port_with_securitygroups() called:port_id=%s"), port_id)
    session = db.get_session()
    sg_binding_port = sg_db.SecurityGroupPortBinding.port_id

    query = session.query(models_v2.Port,
                          sg_db.SecurityGroupPortBinding.security_group_id)
    query = query.outerjoin(sg_db.SecurityGroupPortBinding,
                            models_v2.Port.id == sg_binding_port)
    query = query.filter(models_v2.Port.id == port_id)
    port_and_sgs = query.all()
    if not port_and_sgs:
        return None
    port = port_and_sgs[0][0]
    plugin = manager.QuantumManager.get_plugin()
    port_dict = plugin._make_port_dict(port)
    port_dict[ext_sg.SECURITYGROUPS] = [
        sg_id for port_, sg_id in port_and_sgs if sg_id]
    port_dict['security_group_rules'] = []
    port_dict['security_group_source_groups'] = []
    port_dict['fixed_ips'] = [ip['ip_address']
                              for ip in port['fixed_ips']]
    return port_dict


def set_port_status(port_id, status):
    session = db.get_session()
    try:
        port = session.query(models_v2.Port).filter_by(id=port_id).one()
        port['status'] = status
        session.merge(port)
        session.flush()
    except exc.NoResultFound:
        raise q_exc.PortNotFound(port_id=port_id)


def get_tunnel_endpoints():
    session = db.get_session()
    try:
        tunnels = session.query(ovs_models_v2.TunnelEndpoint).all()
    except exc.NoResultFound:
        return []
    return [{'id': tunnel.id,
             'ip_address': tunnel.ip_address} for tunnel in tunnels]


def _generate_tunnel_id(session):
    try:
        tunnels = session.query(ovs_models_v2.TunnelEndpoint).all()
    except exc.NoResultFound:
        return 0
    tunnel_ids = ([tunnel['id'] for tunnel in tunnels])
    if tunnel_ids:
        id = max(tunnel_ids)
    else:
        id = 0
    return id + 1


def add_tunnel_endpoint(ip):
    session = db.get_session()
    try:
        tunnel = (session.query(ovs_models_v2.TunnelEndpoint).
                  filter_by(ip_address=ip).with_lockmode('update').one())
    except exc.NoResultFound:
        id = _generate_tunnel_id(session)
        tunnel = ovs_models_v2.TunnelEndpoint(ip, id)
        session.add(tunnel)
        session.flush()
    return tunnel

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cisco Systems, Inc.
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
# @author: Aruna Kushwaha, Cisco Systems Inc.
# @author: Abhishek Raut, Cisco Systems Inc.
# @author: Rudrajit Tapadar, Cisco Systems Inc.
# @author: Sergey Sudakovich, Cisco Systems Inc.

import netaddr
import re
from sqlalchemy.orm import exc
from sqlalchemy.sql import and_

from neutron.common import exceptions as q_exc
import neutron.db.api as db
from neutron.db import models_v2
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.common import cisco_constants as c_const
from neutron.plugins.cisco.common import cisco_exceptions as c_exc
from neutron.plugins.cisco.db import n1kv_models_v2

LOG = logging.getLogger(__name__)


def initialize():
    """Initialize the database."""
    db.configure_db()


def del_trunk_segment_binding(db_session, trunk_segment_id, segment_pairs):
    """
    Delete a trunk network binding.

    :param db_session: database session
    :param trunk_segment_id: UUID representing the trunk network
    :param segment_pairs: List of segment UUIDs in pair
                          representing the segments that are trunked
    """
    with db_session.begin(subtransactions=True):
        for (segment_id, dot1qtag) in segment_pairs:
            (db_session.query(n1kv_models_v2.N1kvTrunkSegmentBinding).
             filter_by(trunk_segment_id=trunk_segment_id,
                       segment_id=segment_id,
                       dot1qtag=dot1qtag).delete())
        alloc = (db_session.query(n1kv_models_v2.
                 N1kvTrunkSegmentBinding).
                 filter_by(trunk_segment_id=trunk_segment_id).first())
        if not alloc:
            binding = get_network_binding(db_session, trunk_segment_id)
            binding.physical_network = None


def del_multi_segment_binding(db_session, multi_segment_id, segment_pairs):
    """
    Delete a multi-segment network binding.

    :param db_session: database session
    :param multi_segment_id: UUID representing the multi-segment network
    :param segment_pairs: List of segment UUIDs in pair
                          representing the segments that are bridged
    """
    with db_session.begin(subtransactions=True):
        for (segment1_id, segment2_id) in segment_pairs:
            (db_session.query(n1kv_models_v2.
             N1kvMultiSegmentNetworkBinding).filter_by(
             multi_segment_id=multi_segment_id,
             segment1_id=segment1_id,
             segment2_id=segment2_id).delete())


def add_trunk_segment_binding(db_session, trunk_segment_id, segment_pairs):
    """
    Create a trunk network binding.

    :param db_session: database session
    :param trunk_segment_id: UUID representing the multi-segment network
    :param segment_pairs: List of segment UUIDs in pair
                          representing the segments to be trunked
    """
    with db_session.begin(subtransactions=True):
        binding = get_network_binding(db_session, trunk_segment_id)
        for (segment_id, tag) in segment_pairs:
            if not binding.physical_network:
                member_seg_binding = get_network_binding(db_session,
                                                         segment_id)
                binding.physical_network = member_seg_binding.physical_network
            trunk_segment_binding = (
                n1kv_models_v2.N1kvTrunkSegmentBinding(
                    trunk_segment_id=trunk_segment_id,
                    segment_id=segment_id, dot1qtag=tag))
            db_session.add(trunk_segment_binding)


def add_multi_segment_binding(db_session, multi_segment_id, segment_pairs):
    """
    Create a multi-segment network binding.

    :param db_session: database session
    :param multi_segment_id: UUID representing the multi-segment network
    :param segment_pairs: List of segment UUIDs in pair
                          representing the segments to be bridged
    """
    with db_session.begin(subtransactions=True):
        for (segment1_id, segment2_id) in segment_pairs:
            multi_segment_binding = (
                n1kv_models_v2.N1kvMultiSegmentNetworkBinding(
                    multi_segment_id=multi_segment_id,
                    segment1_id=segment1_id,
                    segment2_id=segment2_id))
            db_session.add(multi_segment_binding)


def add_multi_segment_encap_profile_name(db_session, multi_segment_id,
                                         segment_pair, profile_name):
    """
    Add the encapsulation profile name to the multi-segment network binding.

    :param db_session: database session
    :param multi_segment_id: UUID representing the multi-segment network
    :param segment_pair: set containing the segment UUIDs that are bridged
    """
    with db_session.begin(subtransactions=True):
        binding = get_multi_segment_network_binding(db_session,
                                                    multi_segment_id,
                                                    segment_pair)
        binding.encap_profile_name = profile_name


def get_multi_segment_network_binding(db_session,
                                      multi_segment_id, segment_pair):
    """
    Retrieve multi-segment network binding.

    :param db_session: database session
    :param multi_segment_id: UUID representing the trunk network whose binding
                             is to fetch
    :param segment_pair: set containing the segment UUIDs that are bridged
    :returns: binding object
    """
    try:
        (segment1_id, segment2_id) = segment_pair
        return (db_session.query(
                n1kv_models_v2.N1kvMultiSegmentNetworkBinding).
                filter_by(multi_segment_id=multi_segment_id,
                          segment1_id=segment1_id,
                          segment2_id=segment2_id)).one()
    except exc.NoResultFound:
        raise c_exc.NetworkBindingNotFound(network_id=multi_segment_id)


def get_multi_segment_members(db_session, multi_segment_id):
    """
    Retrieve all the member segments of a multi-segment network.

    :param db_session: database session
    :param multi_segment_id: UUID representing the multi-segment network
    :returns: a list of tuples representing the mapped segments
    """
    with db_session.begin(subtransactions=True):
        allocs = (db_session.query(
                  n1kv_models_v2.N1kvMultiSegmentNetworkBinding).
                  filter_by(multi_segment_id=multi_segment_id))
        return [(a.segment1_id, a.segment2_id) for a in allocs]


def get_multi_segment_encap_dict(db_session, multi_segment_id):
    """
    Retrieve the encapsulation profiles for every segment pairs bridged.

    :param db_session: database session
    :param multi_segment_id: UUID representing the multi-segment network
    :returns: a dictionary of lists containing the segment pairs in sets
    """
    with db_session.begin(subtransactions=True):
        encap_dict = {}
        allocs = (db_session.query(
                  n1kv_models_v2.N1kvMultiSegmentNetworkBinding).
                  filter_by(multi_segment_id=multi_segment_id))
        for alloc in allocs:
            if alloc.encap_profile_name not in encap_dict:
                encap_dict[alloc.encap_profile_name] = []
            seg_pair = (alloc.segment1_id, alloc.segment2_id)
            encap_dict[alloc.encap_profile_name].append(seg_pair)
        return encap_dict


def get_trunk_network_binding(db_session, trunk_segment_id, segment_pair):
    """
    Retrieve trunk network binding.

    :param db_session: database session
    :param trunk_segment_id: UUID representing the trunk network whose binding
                             is to fetch
    :param segment_pair: set containing the segment_id and dot1qtag
    :returns: binding object
    """
    try:
        (segment_id, dot1qtag) = segment_pair
        return (db_session.query(n1kv_models_v2.N1kvTrunkSegmentBinding).
                filter_by(trunk_segment_id=trunk_segment_id,
                          segment_id=segment_id,
                          dot1qtag=dot1qtag)).one()
    except exc.NoResultFound:
        raise c_exc.NetworkBindingNotFound(network_id=trunk_segment_id)


def get_trunk_members(db_session, trunk_segment_id):
    """
    Retrieve all the member segments of a trunk network.

    :param db_session: database session
    :param trunk_segment_id: UUID representing the trunk network
    :returns: a list of tuples representing the segment and their
              corresponding dot1qtag
    """
    with db_session.begin(subtransactions=True):
        allocs = (db_session.query(n1kv_models_v2.N1kvTrunkSegmentBinding).
                  filter_by(trunk_segment_id=trunk_segment_id))
        return [(a.segment_id, a.dot1qtag) for a in allocs]


def is_trunk_member(db_session, segment_id):
    """
    Checks if a segment is a member of a trunk segment.

    :param db_session: database session
    :param segment_id: UUID of the segment to be checked
    :returns: boolean
    """
    with db_session.begin(subtransactions=True):
        ret = (db_session.query(n1kv_models_v2.N1kvTrunkSegmentBinding).
               filter_by(segment_id=segment_id).first())
        return bool(ret)


def is_multi_segment_member(db_session, segment_id):
    """
    Checks if a segment is a member of a multi-segment network.

    :param db_session: database session
    :param segment_id: UUID of the segment to be checked
    :returns: boolean
    """
    with db_session.begin(subtransactions=True):
        ret1 = (db_session.query(
                n1kv_models_v2.N1kvMultiSegmentNetworkBinding).
                filter_by(segment1_id=segment_id).first())
        ret2 = (db_session.query(
                n1kv_models_v2.N1kvMultiSegmentNetworkBinding).
                filter_by(segment2_id=segment_id).first())
        return bool(ret1 or ret2)


def get_network_binding(db_session, network_id):
    """
    Retrieve network binding.

    :param db_session: database session
    :param network_id: UUID representing the network whose binding is
                       to fetch
    :returns: binding object
    """
    try:
        return (db_session.query(n1kv_models_v2.N1kvNetworkBinding).
                filter_by(network_id=network_id).
                one())
    except exc.NoResultFound:
        raise c_exc.NetworkBindingNotFound(network_id=network_id)


def add_network_binding(db_session, network_id, network_type,
                        physical_network, segmentation_id,
                        multicast_ip, network_profile_id, add_segments):
    """
    Create network binding.

    :param db_session: database session
    :param network_id: UUID representing the network
    :param network_type: string representing type of network (VLAN, OVERLAY,
                         MULTI_SEGMENT or TRUNK)
    :param physical_network: Only applicable for VLAN networks. It
                             represents a L2 Domain
    :param segmentation_id: integer representing VLAN or VXLAN ID
    :param multicast_ip: Native VXLAN technology needs a multicast IP to be
                         associated with every VXLAN ID to deal with broadcast
                         packets. A single multicast IP can be shared by
                         multiple VXLAN IDs.
    :param network_profile_id: network profile ID based on which this network
                               is created
    :param add_segments: List of segment UUIDs in pairs to be added to either a
                         multi-segment or trunk network
    """
    with db_session.begin(subtransactions=True):
        binding = n1kv_models_v2.N1kvNetworkBinding(
            network_id=network_id,
            network_type=network_type,
            physical_network=physical_network,
            segmentation_id=segmentation_id,
            multicast_ip=multicast_ip,
            profile_id=network_profile_id)
        db_session.add(binding)
        if add_segments is None:
            pass
        elif network_type == c_const.NETWORK_TYPE_MULTI_SEGMENT:
            add_multi_segment_binding(db_session, network_id, add_segments)
        elif network_type == c_const.NETWORK_TYPE_TRUNK:
            add_trunk_segment_binding(db_session, network_id, add_segments)


def get_segment_range(network_profile):
    """
    Get the segment range min and max for a network profile.

    :params network_profile: object of type network profile
    :returns: integer values representing minimum and maximum segment
              range value
    """
    # Sort the range to ensure min, max is in order
    seg_min, seg_max = sorted(
        int(i) for i in network_profile.segment_range.split('-'))
    LOG.debug(_("seg_min %(seg_min)s, seg_max %(seg_max)s"),
              {'seg_min': seg_min, 'seg_max': seg_max})
    return seg_min, seg_max


def get_multicast_ip(network_profile):
    """
    Retreive a multicast ip from the defined pool.

    :params network_profile: object of type network profile
    :returns: string representing multicast IP
    """
    # Round robin multicast ip allocation
    min_ip, max_ip = _get_multicast_ip_range(network_profile)
    addr_list = list((netaddr.iter_iprange(min_ip, max_ip)))
    mul_ip_str = str(addr_list[network_profile.multicast_ip_index])

    network_profile.multicast_ip_index += 1
    if network_profile.multicast_ip_index == len(addr_list):
        network_profile.multicast_ip_index = 0
    return mul_ip_str


def _get_multicast_ip_range(network_profile):
    """
    Helper method to retrieve minimum and maximum multicast ip.

    :params network_profile: object of type network profile
    :returns: two strings representing minimum multicast ip and
              maximum multicast ip
    """
    # Assumption: ip range belongs to the same subnet
    # Assumption: ip range is already sorted
    return network_profile.multicast_ip_range.split('-')


def get_port_binding(db_session, port_id):
    """
    Retrieve port binding.

    :param db_session: database session
    :param port_id: UUID representing the port whose binding is to fetch
    :returns: port binding object
    """
    try:
        return (db_session.query(n1kv_models_v2.N1kvPortBinding).
                filter_by(port_id=port_id).
                one())
    except exc.NoResultFound:
        raise c_exc.PortBindingNotFound(port_id=port_id)


def add_port_binding(db_session, port_id, policy_profile_id):
    """
    Create port binding.

    Bind the port with policy profile.
    :param db_session: database session
    :param port_id: UUID of the port
    :param policy_profile_id: UUID of the policy profile
    """
    with db_session.begin(subtransactions=True):
        binding = n1kv_models_v2.N1kvPortBinding(port_id=port_id,
                                                 profile_id=policy_profile_id)
        db_session.add(binding)


def _get_sorted_vlan_ids(vlan_ranges):
    """Return sorted allocatable VLAN IDs."""
    vlan_ids = set()
    for vlan_range in vlan_ranges:
        vlan_ids |= set(xrange(vlan_range[0], vlan_range[1] + 1))
    return sorted(vlan_ids)


def sync_vlan_allocations(db_session, network_vlan_ranges):
    """
    Synchronize vlan_allocations table with configured VLAN ranges.

    Sync the network profile range with the vlan_allocations table for each
    physical network.
    :param db_session: database session
    :param network_vlan_ranges: dictionary of network vlan ranges with the
                                physical network name as key.
    """

    with db_session.begin():
        # process vlan ranges for each physical network separately
        for physical_network, vlan_ranges in network_vlan_ranges.items():

            # determine current configured allocatable vlans for this
            # physical network
            vlan_ids = _get_sorted_vlan_ids(vlan_ranges)

            # add missing allocatable vlans to table
            for vlan_id in vlan_ids:
                try:
                    alloc = get_vlan_allocation(db_session,
                                                physical_network,
                                                vlan_id)
                except c_exc.VlanIDNotFound:
                    alloc = n1kv_models_v2.N1kvVlanAllocation(
                        physical_network=physical_network, vlan_id=vlan_id)
                    db_session.add(alloc)


def delete_vlan_allocations(db_session, network_vlan_ranges):
    """
    Delete vlan_allocations for deleted network profile range.

    :param db_session: database session
    :param network_vlan_ranges: dictionary of network vlan ranges with the
                                physical network name as key.
    """

    with db_session.begin():
        # process vlan ranges for each physical network separately
        for physical_network, vlan_ranges in network_vlan_ranges.items():
            # Determine the set of vlan ids which need to be deleted.
            vlan_ids = _get_sorted_vlan_ids(vlan_ranges)
            allocs = (db_session.query(n1kv_models_v2.N1kvVlanAllocation).
                      filter_by(physical_network=physical_network).
                      filter_by(allocated=False))
            for alloc in allocs:
                if alloc.vlan_id in vlan_ids:
                    LOG.debug(_("Removing vlan %(vlan)s on physical "
                                "network %(network)s from pool"),
                              {"vlan": alloc.vlan_id,
                               "network": physical_network})
                    db_session.delete(alloc)


def get_vlan_allocation(db_session, physical_network, vlan_id):
    """
    Retrieve vlan allocation.

    :param db_session: database session
    :param physical network: string name for the physical network
    :param vlan_id: integer representing the VLAN ID.
    :returns: allocation object for given physical network and VLAN ID
    """
    try:
        return (db_session.query(n1kv_models_v2.N1kvVlanAllocation).
                filter_by(physical_network=physical_network,
                          vlan_id=vlan_id).one())
    except exc.NoResultFound:
        raise c_exc.VlanIDNotFound(vlan_id=vlan_id)


def reserve_vlan(db_session, network_profile):
    """
    Reserve a VLAN ID within the range of the network profile.

    :param db_session: database session
    :param network_profile: network profile object
    """
    seg_min, seg_max = get_segment_range(network_profile)
    segment_type = c_const.NETWORK_TYPE_VLAN

    with db_session.begin(subtransactions=True):
        alloc = (db_session.query(n1kv_models_v2.N1kvVlanAllocation).
                 filter(and_(
                        n1kv_models_v2.N1kvVlanAllocation.vlan_id >= seg_min,
                        n1kv_models_v2.N1kvVlanAllocation.vlan_id <= seg_max,
                        n1kv_models_v2.N1kvVlanAllocation.physical_network ==
                        network_profile['physical_network'],
                        n1kv_models_v2.N1kvVlanAllocation.allocated == False)
                        )).first()
        if alloc:
            segment_id = alloc.vlan_id
            physical_network = alloc.physical_network
            alloc.allocated = True
            return (physical_network, segment_type, segment_id, "0.0.0.0")
        raise c_exc.NoMoreNetworkSegments(
            network_profile_name=network_profile.name)


def reserve_vxlan(db_session, network_profile):
    """
    Reserve a VXLAN ID within the range of the network profile.

    :param db_session: database session
    :param network_profile: network profile object
    """
    seg_min, seg_max = get_segment_range(network_profile)
    segment_type = c_const.NETWORK_TYPE_OVERLAY
    physical_network = ""

    with db_session.begin(subtransactions=True):
        alloc = (db_session.query(n1kv_models_v2.N1kvVxlanAllocation).
                 filter(and_(
                        n1kv_models_v2.N1kvVxlanAllocation.vxlan_id >=
                        seg_min,
                        n1kv_models_v2.N1kvVxlanAllocation.vxlan_id <=
                        seg_max,
                        n1kv_models_v2.N1kvVxlanAllocation.allocated == False)
                        ).first())
        if alloc:
            segment_id = alloc.vxlan_id
            alloc.allocated = True
            if network_profile.sub_type == (c_const.
                                            NETWORK_SUBTYPE_NATIVE_VXLAN):
                return (physical_network, segment_type,
                        segment_id, get_multicast_ip(network_profile))
            else:
                return (physical_network, segment_type, segment_id, "0.0.0.0")
        raise q_exc.NoNetworkAvailable()


def alloc_network(db_session, network_profile_id):
    """
    Allocate network using first available free segment ID in segment range.

    :param db_session: database session
    :param network_profile_id: UUID representing the network profile
    """
    with db_session.begin(subtransactions=True):
        network_profile = get_network_profile(db_session,
                                              network_profile_id)
        if network_profile.segment_type == c_const.NETWORK_TYPE_VLAN:
            return reserve_vlan(db_session, network_profile)
        if network_profile.segment_type == c_const.NETWORK_TYPE_OVERLAY:
            return reserve_vxlan(db_session, network_profile)
        return (None, network_profile.segment_type, 0, "0.0.0.0")


def reserve_specific_vlan(db_session, physical_network, vlan_id):
    """
    Reserve a specific VLAN ID for the network.

    :param db_session: database session
    :param physical_network: string representing the name of physical network
    :param vlan_id: integer value of the segmentation ID to be reserved
    """
    with db_session.begin(subtransactions=True):
        try:
            alloc = (db_session.query(n1kv_models_v2.N1kvVlanAllocation).
                     filter_by(physical_network=physical_network,
                               vlan_id=vlan_id).
                     one())
            if alloc.allocated:
                if vlan_id == c_const.FLAT_VLAN_ID:
                    raise q_exc.FlatNetworkInUse(
                        physical_network=physical_network)
                else:
                    raise q_exc.VlanIdInUse(vlan_id=vlan_id,
                                            physical_network=physical_network)
            LOG.debug(_("Reserving specific vlan %(vlan)s on physical "
                        "network %(network)s from pool"),
                      {"vlan": vlan_id, "network": physical_network})
        except exc.NoResultFound:
            LOG.debug(_("Reserving specific vlan %(vlan)s on physical "
                        "network %(network)s outside pool"),
                      {"vlan": vlan_id, "network": physical_network})
            alloc = n1kv_models_v2.N1kvVlanAllocation(
                physical_network=physical_network, vlan_id=vlan_id)
            db_session.add(alloc)
        alloc.allocated = True


def release_vlan(db_session, physical_network, vlan_id, network_vlan_ranges):
    """
    Release a given VLAN ID.

    :param db_session: database session
    :param physical_network: string representing the name of physical network
    :param vlan_id: integer value of the segmentation ID to be released
    :param network_vlan_ranges: dictionary of network vlan ranges with the
                                physical network name as key.
    """
    with db_session.begin(subtransactions=True):
        try:
            alloc = (db_session.query(n1kv_models_v2.N1kvVlanAllocation).
                     filter_by(physical_network=physical_network,
                               vlan_id=vlan_id).
                     one())
            alloc.allocated = False
            for vlan_range in network_vlan_ranges.get(physical_network, []):
                if vlan_range[0] <= vlan_id <= vlan_range[1]:
                    msg = _("Releasing vlan %(vlan)s on physical "
                            "network %(network)s to pool")
                    break
            else:
                db_session.delete(alloc)
                msg = _("Releasing vlan %(vlan)s on physical "
                        "network %(network)s outside pool")
            LOG.debug(msg, {"vlan": vlan_id, "network": physical_network})
        except exc.NoResultFound:
            LOG.warning(_("vlan_id %(vlan)s on physical network %(network)s "
                          "not found"),
                        {"vlan": vlan_id, "network": physical_network})


def _get_sorted_vxlan_ids(vxlan_id_ranges):
    """Return sorted VXLAN IDs."""
    vxlan_ids = set()
    for vxlan_min, vxlan_max in vxlan_id_ranges:
        if vxlan_max + 1 - vxlan_min > c_const.MAX_VXLAN_RANGE:
            LOG.error(_("Skipping unreasonable vxlan ID range %(vxlan_min)s - "
                        "%(vxlan_max)s"),
                      {"vxlan_min": vxlan_min, "vxlan_max": vxlan_max})
        else:
            vxlan_ids |= set(xrange(vxlan_min, vxlan_max + 1))
    return sorted(vxlan_ids)


def sync_vxlan_allocations(db_session, vxlan_id_ranges):
    """
    Synchronize vxlan_allocations table with configured vxlan ranges.

    :param db_session: database session
    :param vxlan_id_ranges: list of segment range tuples
    """

    vxlan_ids = _get_sorted_vxlan_ids(vxlan_id_ranges)
    with db_session.begin():
        for vxlan_id in vxlan_ids:
            alloc = get_vxlan_allocation(db_session, vxlan_id)
            if not alloc:
                alloc = n1kv_models_v2.N1kvVxlanAllocation(vxlan_id=vxlan_id)
                db_session.add(alloc)


def delete_vxlan_allocations(db_session, vxlan_id_ranges):
    """
    Delete vxlan_allocations for deleted network profile range.

    :param db_session: database session
    :param vxlan_id_ranges: list of segment range tuples
    """
    vxlan_ids = _get_sorted_vxlan_ids(vxlan_id_ranges)
    with db_session.begin():
        allocs = (db_session.query(n1kv_models_v2.N1kvVxlanAllocation).
                  filter_by(allocated=False))
        for alloc in allocs:
            if alloc.vxlan_id in vxlan_ids:
                LOG.debug(_("Removing vxlan %s from pool"),
                          alloc.vxlan_id)
                db_session.delete(alloc)


def get_vxlan_allocation(db_session, vxlan_id):
    """
    Retrieve VXLAN allocation for the given VXLAN ID.

    :param db_session: database session
    :param vxlan_id: integer value representing the segmentation ID
    :returns: allocation object
    """
    return (db_session.query(n1kv_models_v2.N1kvVxlanAllocation).
            filter_by(vxlan_id=vxlan_id).first())


def reserve_specific_vxlan(db_session, vxlan_id):
    """
    Reserve a specific VXLAN ID.

    :param db_session: database session
    :param vxlan_id: integer value representing the segmentation ID
    """
    with db_session.begin(subtransactions=True):
        try:
            alloc = (db_session.query(n1kv_models_v2.N1kvVxlanAllocation).
                     filter_by(vxlan_id=vxlan_id).
                     one())
            if alloc.allocated:
                raise c_exc.VxlanIdInUse(vxlan_id=vxlan_id)
            LOG.debug(_("Reserving specific vxlan %s from pool"), vxlan_id)
        except exc.NoResultFound:
            LOG.debug(_("Reserving specific vxlan %s outside pool"), vxlan_id)
            alloc = n1kv_models_v2.N1kvVxlanAllocation(vxlan_id=vxlan_id)
            db_session.add(alloc)
        alloc.allocated = True


def release_vxlan(db_session, vxlan_id, vxlan_id_ranges):
    """
    Release a given VXLAN ID.

    :param db_session: database session
    :param vxlan_id: integer value representing the segmentation ID
    :param vxlan_id_ranges: list of the segment range tuples.
    """
    with db_session.begin(subtransactions=True):
        try:
            alloc = (db_session.query(n1kv_models_v2.N1kvVxlanAllocation).
                     filter_by(vxlan_id=vxlan_id).
                     one())
            alloc.allocated = False
            for vxlan_id_range in vxlan_id_ranges:
                if vxlan_id_range[0] <= vxlan_id <= vxlan_id_range[1]:
                    msg = _("Releasing vxlan %s to pool")
                    break
            else:
                db_session.delete(alloc)
                msg = _("Releasing vxlan %s outside pool")
            LOG.debug(msg, vxlan_id)
        except exc.NoResultFound:
            LOG.warning(_("vxlan_id %s not found"), vxlan_id)


def set_port_status(port_id, status):
    """
    Set the status of the port.

    :param port_id: UUID representing the port
    :param status: string representing the new status
    """
    db_session = db.get_session()
    try:
        port = db_session.query(models_v2.Port).filter_by(id=port_id).one()
        port.status = status
    except exc.NoResultFound:
        raise q_exc.PortNotFound(port_id=port_id)


def get_vm_network(db_session, policy_profile_id, network_id):
    """
    Retrieve a vm_network based on policy profile and network id.

    :param db_session: database session
    :param policy_profile_id: UUID representing policy profile
    :param network_id: UUID representing network
    :returns: VM network object
    """
    try:
        return (db_session.query(n1kv_models_v2.N1kVmNetwork).
                filter_by(profile_id=policy_profile_id,
                          network_id=network_id).one())
    except exc.NoResultFound:
        name = (c_const.VM_NETWORK_NAME_PREFIX + policy_profile_id
                + "_" + network_id)
        raise c_exc.VMNetworkNotFound(name=name)


def add_vm_network(db_session,
                   name,
                   policy_profile_id,
                   network_id,
                   port_count):
    """
    Create a VM network.

    Add a VM network for a unique combination of network and
    policy profile. All ports having the same policy profile
    on one network will be associated with one VM network.
    :param db_session: database session
    :param name: string representing the name of the VM network
    :param policy_profile_id: UUID representing policy profile
    :param network_id: UUID representing a network
    :param port_count: integer representing the number of ports on vm network
    """
    with db_session.begin(subtransactions=True):
        vm_network = n1kv_models_v2.N1kVmNetwork(
            name=name,
            profile_id=policy_profile_id,
            network_id=network_id,
            port_count=port_count)
        db_session.add(vm_network)


def update_vm_network_port_count(db_session, name, port_count):
    """
    Update a VM network with new port count.

    :param db_session: database session
    :param name: string representing the name of the VM network
    :param port_count: integer representing the number of ports on VM network
    """
    try:
        with db_session.begin(subtransactions=True):
            vm_network = (db_session.query(n1kv_models_v2.N1kVmNetwork).
                          filter_by(name=name).one())
            if port_count is not None:
                vm_network.port_count = port_count
            return vm_network
    except exc.NoResultFound:
        raise c_exc.VMNetworkNotFound(name=name)


def delete_vm_network(db_session, policy_profile_id, network_id):
    """
    Delete a VM network.

    :param db_session: database session
    :param policy_profile_id: UUID representing a policy profile
    :param network_id: UUID representing a network
    :returns: deleted VM network object
    """
    with db_session.begin(subtransactions=True):
        try:
            vm_network = get_vm_network(db_session,
                                        policy_profile_id,
                                        network_id)
            db_session.delete(vm_network)
            db_session.query(n1kv_models_v2.N1kVmNetwork).filter_by(
                name=vm_network["name"]).delete()
            return vm_network
        except exc.NoResultFound:
            name = (c_const.VM_NETWORK_NAME_PREFIX + policy_profile_id +
                    "_" + network_id)
            raise c_exc.VMNetworkNotFound(name=name)


def create_network_profile(db_session, network_profile):
    """Create a network profile."""
    LOG.debug(_("create_network_profile()"))
    with db_session.begin(subtransactions=True):
        kwargs = {"name": network_profile["name"],
                  "segment_type": network_profile["segment_type"]}
        if network_profile["segment_type"] == c_const.NETWORK_TYPE_VLAN:
            kwargs["physical_network"] = network_profile["physical_network"]
            kwargs["segment_range"] = network_profile["segment_range"]
        elif network_profile["segment_type"] == c_const.NETWORK_TYPE_OVERLAY:
            kwargs["multicast_ip_index"] = 0
            kwargs["multicast_ip_range"] = network_profile[
                "multicast_ip_range"]
            kwargs["segment_range"] = network_profile["segment_range"]
            kwargs["sub_type"] = network_profile["sub_type"]
        elif network_profile["segment_type"] == c_const.NETWORK_TYPE_TRUNK:
            kwargs["sub_type"] = network_profile["sub_type"]
        net_profile = n1kv_models_v2.NetworkProfile(**kwargs)
        db_session.add(net_profile)
        return net_profile


def delete_network_profile(db_session, id):
    """Delete Network Profile."""
    LOG.debug(_("delete_network_profile()"))
    with db_session.begin(subtransactions=True):
        try:
            network_profile = get_network_profile(db_session, id)
            db_session.delete(network_profile)
            (db_session.query(n1kv_models_v2.ProfileBinding).
             filter_by(profile_id=id).delete())
            return network_profile
        except exc.NoResultFound:
            raise c_exc.ProfileTenantBindingNotFound(profile_id=id)


def update_network_profile(db_session, id, network_profile):
    """Update Network Profile."""
    LOG.debug(_("update_network_profile()"))
    with db_session.begin(subtransactions=True):
        profile = get_network_profile(db_session, id)
        profile.update(network_profile)
        return profile


def get_network_profile(db_session, id):
    """Get Network Profile."""
    LOG.debug(_("get_network_profile()"))
    try:
        return db_session.query(
            n1kv_models_v2.NetworkProfile).filter_by(id=id).one()
    except exc.NoResultFound:
        raise c_exc.NetworkProfileNotFound(profile=id)


def _get_network_profiles(**kwargs):
    """
    Retrieve all network profiles.

    Get Network Profiles on a particular physical network, if physical
    network is specified. If no physical network is specified, return
    all network profiles.
    """
    db_session = db.get_session()
    if "physical_network" in kwargs:
        return (db_session.query(n1kv_models_v2.NetworkProfile).
                filter_by(physical_network=kwargs["physical_network"]))
    return db_session.query(n1kv_models_v2.NetworkProfile)


def create_policy_profile(policy_profile):
    """Create Policy Profile."""
    LOG.debug(_("create_policy_profile()"))
    db_session = db.get_session()
    with db_session.begin(subtransactions=True):
        p_profile = n1kv_models_v2.PolicyProfile(id=policy_profile["id"],
                                                 name=policy_profile["name"])
        db_session.add(p_profile)
        return p_profile


def delete_policy_profile(id):
    """Delete Policy Profile."""
    LOG.debug(_("delete_policy_profile()"))
    db_session = db.get_session()
    with db_session.begin(subtransactions=True):
        policy_profile = get_policy_profile(db_session, id)
        db_session.delete(policy_profile)


def update_policy_profile(db_session, id, policy_profile):
    """Update a policy profile."""
    LOG.debug(_("update_policy_profile()"))
    with db_session.begin(subtransactions=True):
        _profile = get_policy_profile(db_session, id)
        _profile.update(policy_profile)
        return _profile


def get_policy_profile(db_session, id):
    """Get Policy Profile."""
    LOG.debug(_("get_policy_profile()"))
    try:
        return db_session.query(
            n1kv_models_v2.PolicyProfile).filter_by(id=id).one()
    except exc.NoResultFound:
        raise c_exc.PolicyProfileIdNotFound(profile_id=id)


def create_profile_binding(tenant_id, profile_id, profile_type):
    """Create Network/Policy Profile association with a tenant."""
    if profile_type not in ["network", "policy"]:
        raise q_exc.NeutronException(_("Invalid profile type"))

    if _profile_binding_exists(tenant_id, profile_id, profile_type):
        return get_profile_binding(tenant_id, profile_id)

    db_session = db.get_session()
    with db_session.begin(subtransactions=True):
        binding = n1kv_models_v2.ProfileBinding(profile_type=profile_type,
                                                profile_id=profile_id,
                                                tenant_id=tenant_id)
        db_session.add(binding)
        return binding


def _profile_binding_exists(tenant_id, profile_id, profile_type):
    db_session = db.get_session()
    LOG.debug(_("_profile_binding_exists()"))
    return (db_session.query(n1kv_models_v2.ProfileBinding).
            filter_by(tenant_id=tenant_id, profile_id=profile_id,
                      profile_type=profile_type).first())


def _get_profile_binding(tenant_id, profile_id):
    LOG.debug(_("_get_profile_binding"))
    db_session = db.get_session()
    return (db_session.query(n1kv_models_v2.ProfileBinding).filter_by(
        tenant_id=tenant_id, profile_id=profile_id).one())


def get_profile_binding(tenant_id, profile_id):
    """Get Network/Policy Profile - Tenant binding."""
    LOG.debug(_("get_profile_binding()"))
    try:
        return _get_profile_binding(tenant_id, profile_id)
    except exc.NoResultFound:
        c_exc.ProfileTenantBindingNotFound(profile_id=profile_id)


def delete_profile_binding(tenant_id, profile_id):
    """Delete Policy Binding."""
    LOG.debug(_("delete_profile_binding()"))
    db_session = db.get_session()
    try:
        binding = get_profile_binding(tenant_id, profile_id)
        with db_session.begin(subtransactions=True):
            db_session.delete(binding)
    except c_exc.ProfileTenantBindingNotFound:
        LOG.debug(_("Profile-Tenant binding missing for profile ID "
                    "%(profile_id)s and tenant ID %(tenant_id)s"),
                  {"profile_id": profile_id, "tenant_id": tenant_id})
        return


def _get_profile_bindings(profile_type=None):
    """
    Retrieve a list of profile bindings.

    Get all profile-tenant bindings based on profile type.
    If profile type is None, return profile-tenant binding for all
    profile types.
    """
    LOG.debug(_("_get_profile_bindings()"))
    db_session = db.get_session()
    if profile_type:
        profile_bindings = (db_session.query(n1kv_models_v2.ProfileBinding).
                            filter_by(profile_type=profile_type))
        return profile_bindings
    return db_session.query(n1kv_models_v2.ProfileBinding)


class NetworkProfile_db_mixin(object):

    """Network Profile Mixin."""

    def _replace_fake_tenant_id_with_real(self, context):
        """
        Replace default tenant-id with admin tenant-ids.

        Default tenant-ids are populated in profile bindings when plugin is
        initialized. Replace these tenant-ids with admin's tenant-id.
        :param context: neutron api request context
        """
        if context.is_admin and context.tenant_id:
            tenant_id = context.tenant_id
            db_session = context.session
            with db_session.begin(subtransactions=True):
                (db_session.query(n1kv_models_v2.ProfileBinding).
                 filter_by(tenant_id=c_const.TENANT_ID_NOT_SET).
                 update({'tenant_id': tenant_id}))

    def _get_network_collection_for_tenant(self, db_session, model, tenant_id):
        net_profile_ids = (db_session.query(n1kv_models_v2.ProfileBinding.
                                            profile_id).
                           filter_by(tenant_id=tenant_id).
                           filter_by(profile_type=c_const.NETWORK))
        network_profiles = (db_session.query(model).filter(model.id.in_(
            pid[0] for pid in net_profile_ids)))
        return [self._make_network_profile_dict(p) for p in network_profiles]

    def _make_profile_bindings_dict(self, profile_binding, fields=None):
        res = {"profile_id": profile_binding["profile_id"],
               "tenant_id": profile_binding["tenant_id"]}
        return self._fields(res, fields)

    def _make_network_profile_dict(self, network_profile, fields=None):
        res = {"id": network_profile["id"],
               "name": network_profile["name"],
               "segment_type": network_profile["segment_type"],
               "sub_type": network_profile["sub_type"],
               "segment_range": network_profile["segment_range"],
               "multicast_ip_index": network_profile["multicast_ip_index"],
               "multicast_ip_range": network_profile["multicast_ip_range"],
               "physical_network": network_profile["physical_network"]}
        return self._fields(res, fields)

    def get_network_profile_bindings(self, context, filters=None, fields=None):
        """
        Retrieve a list of profile bindings for network profiles.

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for a
                        profile bindings object. Values in this dictiontary are
                        an iterable containing values that will be used for an
                        exact match comparison for that value. Each result
                        returned by this function will have matched one of the
                        values for each key in filters
        :params fields: a list of strings that are valid keys in a profile
                        bindings dictionary. Only these fields will be returned
        :returns: list of profile bindings
        """
        if context.is_admin:
            profile_bindings = _get_profile_bindings(
                profile_type=c_const.NETWORK)
            return [self._make_profile_bindings_dict(pb)
                    for pb in profile_bindings]

    def create_network_profile(self, context, network_profile):
        """
        Create a network profile.

        :param context: neutron api request context
        :param network_profile: network profile dictionary
        :returns: network profile dictionary
        """
        self._replace_fake_tenant_id_with_real(context)
        p = network_profile["network_profile"]
        self._validate_network_profile_args(context, p)
        net_profile = create_network_profile(context.session, p)
        create_profile_binding(context.tenant_id,
                               net_profile.id,
                               c_const.NETWORK)
        if p.get("add_tenant"):
            self.add_network_profile_tenant(net_profile.id, p["add_tenant"])
        return self._make_network_profile_dict(net_profile)

    def delete_network_profile(self, context, id):
        """
        Delete a network profile.

        :param context: neutron api request context
        :param id: UUID representing network profile to delete
        :returns: deleted network profile dictionary
        """
        _profile = delete_network_profile(context.session, id)
        return self._make_network_profile_dict(_profile)

    def update_network_profile(self, context, id, network_profile):
        """
        Update a network profile.

        Add/remove network profile to tenant-id binding for the corresponding
        options and if user is admin.
        :param context: neutron api request context
        :param id: UUID representing network profile to update
        :param network_profile: network profile dictionary
        :returns: updated network profile dictionary
        """
        p = network_profile["network_profile"]
        if context.is_admin and "add_tenant" in p:
            self.add_network_profile_tenant(id, p["add_tenant"])
            return self._make_network_profile_dict(get_network_profile(
                context.session, id))
        if context.is_admin and "remove_tenant" in p:
            delete_profile_binding(p["remove_tenant"], id)
            return self._make_network_profile_dict(get_network_profile(
                context.session, id))
        return self._make_network_profile_dict(
            update_network_profile(context.session, id, p))

    def get_network_profile(self, context, id, fields=None):
        """
        Retrieve a network profile.

        :param context: neutron api request context
        :param id: UUID representing the network profile to retrieve
        :params fields: a list of strings that are valid keys in a  network
                        profile dictionary. Only these fields will be returned
        :returns: network profile dictionary
        """
        profile = get_network_profile(context.session, id)
        return self._make_network_profile_dict(profile, fields)

    def get_network_profiles(self, context, filters=None, fields=None):
        """
        Retrieve a list of all network profiles.

        Retrieve all network profiles if tenant is admin. For a non-admin
        tenant, retrieve all network profiles belonging to this tenant only.
        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for a
                        network profile object. Values in this dictiontary are
                        an iterable containing values that will be used for an
                        exact match comparison for that value. Each result
                        returned by this function will have matched one of the
                        values for each key in filters
        :params fields: a list of strings that are valid keys in a  network
                        profile dictionary. Only these fields will be returned
        :returns: list of all network profiles
        """
        if context.is_admin:
            return self._get_collection(context, n1kv_models_v2.NetworkProfile,
                                        self._make_network_profile_dict,
                                        filters=filters, fields=fields)
        return self._get_network_collection_for_tenant(context.session,
                                                       n1kv_models_v2.
                                                       NetworkProfile,
                                                       context.tenant_id)

    def add_network_profile_tenant(self, network_profile_id, tenant_id):
        """
        Add a tenant to a network profile.

        :param network_profile_id: UUID representing network profile
        :param tenant_id: UUID representing the tenant
        :returns: profile binding object
        """
        return create_profile_binding(tenant_id,
                                      network_profile_id,
                                      c_const.NETWORK)

    def network_profile_exists(self, context, id):
        """
        Verify whether a network profile for given id exists.

        :param context: neutron api request context
        :param id: UUID representing network profile
        :returns: true if network profile exist else False
        """
        try:
            get_network_profile(context.session, id)
            return True
        except c_exc.NetworkProfileNotFound(profile=id):
            return False

    def _get_segment_range(self, data):
        # Sort the range to ensure min, max is in order
        return sorted(int(seg) for seg in data.split("-")[:2])

    def _validate_network_profile_args(self, context, p):
        """
        Validate completeness of Nexus1000V network profile arguments.

        :param context: neutron api request context
        :param p: network profile object
        """
        self._validate_network_profile(p)
        self._validate_segment_range_uniqueness(context, p)

    def _validate_segment_range(self, network_profile):
        """
        Validate segment range values.

        :param network_profile: network profile object
        """
        if not re.match(r"(\d+)\-(\d+)", network_profile["segment_range"]):
            msg = _("Invalid segment range. example range: 500-550")
            raise q_exc.InvalidInput(error_message=msg)

    def _validate_network_profile(self, net_p):
        """
        Validate completeness of a network profile arguments.

        :param net_p: network profile object
        """
        if any(net_p[arg] == "" for arg in ["segment_type"]):
            msg = _("Arguments segment_type missing"
                    " for network profile")
            LOG.exception(msg)
            raise q_exc.InvalidInput(error_message=msg)
        segment_type = net_p["segment_type"].lower()
        if segment_type not in [c_const.NETWORK_TYPE_VLAN,
                                c_const.NETWORK_TYPE_OVERLAY,
                                c_const.NETWORK_TYPE_TRUNK,
                                c_const.NETWORK_TYPE_MULTI_SEGMENT]:
            msg = _("segment_type should either be vlan, overlay, "
                    "multi-segment or trunk")
            LOG.exception(msg)
            raise q_exc.InvalidInput(error_message=msg)
        if segment_type == c_const.NETWORK_TYPE_VLAN:
            if "physical_network" not in net_p:
                msg = _("Argument physical_network missing "
                        "for network profile")
                LOG.exception(msg)
                raise q_exc.InvalidInput(error_message=msg)
        if segment_type in [c_const.NETWORK_TYPE_TRUNK,
                            c_const.NETWORK_TYPE_OVERLAY]:
            if "sub_type" not in net_p:
                msg = _("Argument sub_type missing "
                        "for network profile")
                LOG.exception(msg)
                raise q_exc.InvalidInput(error_message=msg)
        if segment_type in [c_const.NETWORK_TYPE_VLAN,
                            c_const.NETWORK_TYPE_OVERLAY]:
            if "segment_range" not in net_p:
                msg = _("Argument segment_range missing "
                        "for network profile")
                LOG.exception(msg)
                raise q_exc.InvalidInput(error_message=msg)
            self._validate_segment_range(net_p)
        if segment_type == c_const.NETWORK_TYPE_OVERLAY:
            if net_p['sub_type'] != c_const.NETWORK_SUBTYPE_NATIVE_VXLAN:
                net_p['multicast_ip_range'] = '0.0.0.0'
        else:
            net_p['multicast_ip_range'] = '0.0.0.0'

    def _validate_segment_range_uniqueness(self, context, net_p):
        """
        Validate that segment range doesn't overlap.

        :param context: neutron api request context
        :param net_p: network profile dictionary
        """
        segment_type = net_p["segment_type"].lower()
        if segment_type == c_const.NETWORK_TYPE_VLAN:
            profiles = _get_network_profiles(
                physical_network=net_p["physical_network"])
        else:
            profiles = _get_network_profiles()
        if profiles:
            for profile in profiles:
                name = profile.name
                segment_range = profile.segment_range
                if net_p["name"] == name:
                    msg = (_("NetworkProfile name %s already exists"),
                           net_p["name"])
                    LOG.exception(msg)
                    raise q_exc.InvalidInput(error_message=msg)
                if (c_const.NETWORK_TYPE_MULTI_SEGMENT in
                    [profile.segment_type, net_p["segment_type"]] or
                    c_const.NETWORK_TYPE_TRUNK in
                    [profile.segment_type, net_p["segment_type"]]):
                    continue
                seg_min, seg_max = self._get_segment_range(
                    net_p["segment_range"])
                profile_seg_min, profile_seg_max = self._get_segment_range(
                    segment_range)
                if ((profile_seg_min <= seg_min <= profile_seg_max) or
                    (profile_seg_min <= seg_max <= profile_seg_max) or
                    ((seg_min <= profile_seg_min) and
                     (seg_max >= profile_seg_max))):
                    msg = _("Segment range overlaps with another profile")
                    LOG.exception(msg)
                    raise q_exc.InvalidInput(error_message=msg)

    def _get_network_profile_by_name(self, db_session, name):
        """
        Retrieve network profile based on name.

        :param db_session: database session
        :param name: string representing the name for the network profile
        :returns: network profile object
        """
        with db_session.begin(subtransactions=True):
            try:
                return (db_session.query(n1kv_models_v2.NetworkProfile).
                        filter_by(name=name).one())
            except exc.NoResultFound:
                raise c_exc.NetworkProfileNotFound(profile=name)


class PolicyProfile_db_mixin(object):

    """Policy Profile Mixin."""

    def _get_policy_collection_for_tenant(self, db_session, model, tenant_id):
        profile_ids = (db_session.query(n1kv_models_v2.
                       ProfileBinding.profile_id)
                       .filter_by(tenant_id=tenant_id).
                       filter_by(profile_type=c_const.POLICY).all())
        profiles = db_session.query(model).filter(model.id.in_(
            pid[0] for pid in profile_ids))
        return [self._make_policy_profile_dict(p) for p in profiles]

    def _make_policy_profile_dict(self, policy_profile, fields=None):
        res = {"id": policy_profile["id"], "name": policy_profile["name"]}
        return self._fields(res, fields)

    def _make_profile_bindings_dict(self, profile_binding, fields=None):
        res = {"profile_id": profile_binding["profile_id"],
               "tenant_id": profile_binding["tenant_id"]}
        return self._fields(res, fields)

    def _policy_profile_exists(self, id):
        db_session = db.get_session()
        return (db_session.query(n1kv_models_v2.PolicyProfile).
                filter_by(id=id).first())

    def get_policy_profile(self, context, id, fields=None):
        """
        Retrieve a policy profile for the given UUID.

        :param context: neutron api request context
        :param id: UUID representing policy profile to fetch
        :params fields: a list of strings that are valid keys in a policy
                        profile dictionary. Only these fields will be returned
        :returns: policy profile dictionary
        """
        profile = get_policy_profile(context.session, id)
        return self._make_policy_profile_dict(profile, fields)

    def get_policy_profiles(self, context, filters=None, fields=None):
        """
        Retrieve a list of policy profiles.

        Retrieve all policy profiles if tenant is admin. For a non-admin
        tenant, retrieve all policy profiles belonging to this tenant only.
        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for a
                        policy profile object. Values in this dictiontary are
                        an iterable containing values that will be used for an
                        exact match comparison for that value. Each result
                        returned by this function will have matched one of the
                        values for each key in filters
        :params fields: a list of strings that are valid keys in a policy
                        profile dictionary. Only these fields will be returned
        :returns: list of all policy profiles
        """
        if context.is_admin:
            return self._get_collection(context, n1kv_models_v2.PolicyProfile,
                                        self._make_policy_profile_dict,
                                        filters=filters, fields=fields)
        else:
            return self._get_policy_collection_for_tenant(context.session,
                                                          n1kv_models_v2.
                                                          PolicyProfile,
                                                          context.tenant_id)

    def get_policy_profile_bindings(self, context, filters=None, fields=None):
        """
        Retrieve a list of profile bindings for policy profiles.

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for a
                        profile bindings object. Values in this dictiontary are
                        an iterable containing values that will be used for an
                        exact match comparison for that value. Each result
                        returned by this function will have matched one of the
                        values for each key in filters
        :params fields: a list of strings that are valid keys in a profile
                        bindings dictionary. Only these fields will be returned
        :returns: list of profile bindings
        """
        if context.is_admin:
            profile_bindings = _get_profile_bindings(
                profile_type=c_const.POLICY)
            return [self._make_profile_bindings_dict(pb)
                    for pb in profile_bindings]

    def update_policy_profile(self, context, id, policy_profile):
        """
        Update a policy profile.

        Add/remove policy profile to tenant-id binding for the corresponding
        option and if user is admin.
        :param context: neutron api request context
        :param id: UUID representing policy profile to update
        :param policy_profile: policy profile dictionary
        :returns: updated policy profile dictionary
        """
        p = policy_profile["policy_profile"]
        if context.is_admin and "add_tenant" in p:
            self.add_policy_profile_tenant(id, p["add_tenant"])
            return self._make_policy_profile_dict(get_policy_profile(
                context.session, id))
        if context.is_admin and "remove_tenant" in p:
            delete_profile_binding(p["remove_tenant"], id)
            return self._make_policy_profile_dict(get_policy_profile(
                context.session, id))
        return self._make_policy_profile_dict(
            update_policy_profile(context.session, id, p))

    def add_policy_profile_tenant(self, policy_profile_id, tenant_id):
        """
        Add a tenant to a policy profile binding.

        :param policy_profile_id: UUID representing policy profile
        :param tenant_id: UUID representing the tenant
        :returns: profile binding object
        """
        return create_profile_binding(tenant_id,
                                      policy_profile_id,
                                      c_const.POLICY)

    def remove_policy_profile_tenant(self, policy_profile_id, tenant_id):
        """
        Remove a tenant to a policy profile binding.

        :param policy_profile_id: UUID representing policy profile
        :param tenant_id: UUID representing the tenant
        """
        delete_profile_binding(tenant_id, policy_profile_id)

    def _delete_policy_profile(self, policy_profile_id):
        """Delete policy profile and associated binding."""
        db_session = db.get_session()
        with db_session.begin(subtransactions=True):
            (db_session.query(n1kv_models_v2.PolicyProfile).
             filter_by(id=policy_profile_id).delete())

    def _get_policy_profile_by_name(self, name):
        """
        Retrieve policy profile based on name.

        :param name: string representing the name for the policy profile
        :returns: policy profile object
        """
        db_session = db.get_session()
        with db_session.begin(subtransactions=True):
            return (db_session.query(n1kv_models_v2.PolicyProfile).
                    filter_by(name=name).one())

    def _remove_all_fake_policy_profiles(self):
        """
        Remove all policy profiles associated with fake tenant id.

        This will find all Profile ID where tenant is not set yet - set A
        and profiles where tenant was already set - set B
        and remove what is in both and no tenant id set
        """
        db_session = db.get_session()
        with db_session.begin(subtransactions=True):
            a_set_q = (db_session.query(n1kv_models_v2.ProfileBinding).
                       filter_by(tenant_id=c_const.TENANT_ID_NOT_SET,
                       profile_type=c_const.POLICY))
            a_set = set(i.profile_id for i in a_set_q)
            b_set_q = (db_session.query(n1kv_models_v2.ProfileBinding).
                       filter(and_(n1kv_models_v2.ProfileBinding.
                                   tenant_id != c_const.TENANT_ID_NOT_SET,
                                   n1kv_models_v2.ProfileBinding.
                                   profile_type == c_const.POLICY)))
            b_set = set(i.profile_id for i in b_set_q)
            (db_session.query(n1kv_models_v2.ProfileBinding).
             filter(and_(n1kv_models_v2.ProfileBinding.profile_id.
                         in_(a_set & b_set), n1kv_models_v2.ProfileBinding.
                         tenant_id == c_const.TENANT_ID_NOT_SET)).
             delete(synchronize_session="fetch"))

    def _add_policy_profile(self,
                            policy_profile_name,
                            policy_profile_id,
                            tenant_id=None):
        """
        Add Policy profile and tenant binding.

        :param policy_profile_name: string representing the name for the
                                    policy profile
        :param policy_profile_id: UUID representing the policy profile
        :param tenant_id: UUID representing the tenant
        """
        policy_profile = {"id": policy_profile_id, "name": policy_profile_name}
        tenant_id = tenant_id or c_const.TENANT_ID_NOT_SET
        if not self._policy_profile_exists(policy_profile_id):
            create_policy_profile(policy_profile)
        create_profile_binding(tenant_id, policy_profile["id"], c_const.POLICY)

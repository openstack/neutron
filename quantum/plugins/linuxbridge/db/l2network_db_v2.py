# Copyright (c) 2012 OpenStack Foundation.
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


from sqlalchemy.orm import exc

from quantum.common import exceptions as q_exc
import quantum.db.api as db
from quantum.db import models_v2
from quantum.db import securitygroups_db as sg_db
from quantum import manager
from quantum.openstack.common import log as logging
from quantum.plugins.linuxbridge.common import config  # noqa
from quantum.plugins.linuxbridge.common import constants
from quantum.plugins.linuxbridge.db import l2network_models_v2

LOG = logging.getLogger(__name__)


def initialize():
    db.configure_db()


def sync_network_states(network_vlan_ranges):
    """Synchronize network_states table with current configured VLAN ranges."""

    session = db.get_session()
    with session.begin():
        # get existing allocations for all physical networks
        allocations = dict()
        states = (session.query(l2network_models_v2.NetworkState).
                  all())
        for state in states:
            if state.physical_network not in allocations:
                allocations[state.physical_network] = set()
            allocations[state.physical_network].add(state)

        # process vlan ranges for each configured physical network
        for physical_network, vlan_ranges in network_vlan_ranges.iteritems():
            # determine current configured allocatable vlans for this
            # physical network
            vlan_ids = set()
            for vlan_range in vlan_ranges:
                vlan_ids |= set(xrange(vlan_range[0], vlan_range[1] + 1))

            # remove from table unallocated vlans not currently allocatable
            if physical_network in allocations:
                for state in allocations[physical_network]:
                    try:
                        # see if vlan is allocatable
                        vlan_ids.remove(state.vlan_id)
                    except KeyError:
                        # it's not allocatable, so check if its allocated
                        if not state.allocated:
                            # it's not, so remove it from table
                            LOG.debug(_("Removing vlan %(vlan_id)s on "
                                        "physical network %(physical_network)s"
                                        " from pool"),
                                      {'vlan_id': state.vlan_id,
                                       'physical_network': physical_network})
                            session.delete(state)
                del allocations[physical_network]

            # add missing allocatable vlans to table
            for vlan_id in sorted(vlan_ids):
                state = l2network_models_v2.NetworkState(physical_network,
                                                         vlan_id)
                session.add(state)

        # remove from table unallocated vlans for any unconfigured physical
        # networks
        for states in allocations.itervalues():
            for state in states:
                if not state.allocated:
                    LOG.debug(_("Removing vlan %(vlan_id)s on physical "
                                "network %(physical_network)s"
                                " from pool"),
                              {'vlan_id': state.vlan_id,
                               'physical_network': physical_network})
                    session.delete(state)


def get_network_state(physical_network, vlan_id):
    """Get state of specified network"""

    session = db.get_session()
    try:
        state = (session.query(l2network_models_v2.NetworkState).
                 filter_by(physical_network=physical_network,
                           vlan_id=vlan_id).
                 one())
        return state
    except exc.NoResultFound:
        return None


def reserve_network(session):
    with session.begin(subtransactions=True):
        state = (session.query(l2network_models_v2.NetworkState).
                 filter_by(allocated=False).
                 with_lockmode('update').
                 first())
        if not state:
            raise q_exc.NoNetworkAvailable()
        LOG.debug(_("Reserving vlan %(vlan_id)s on physical network "
                    "%(physical_network)s from pool"),
                  {'vlan_id': state.vlan_id,
                   'physical_network': state.physical_network})
        state.allocated = True
    return (state.physical_network, state.vlan_id)


def reserve_specific_network(session, physical_network, vlan_id):
    with session.begin(subtransactions=True):
        try:
            state = (session.query(l2network_models_v2.NetworkState).
                     filter_by(physical_network=physical_network,
                               vlan_id=vlan_id).
                     with_lockmode('update').
                     one())
            if state.allocated:
                if vlan_id == constants.FLAT_VLAN_ID:
                    raise q_exc.FlatNetworkInUse(
                        physical_network=physical_network)
                else:
                    raise q_exc.VlanIdInUse(vlan_id=vlan_id,
                                            physical_network=physical_network)
            LOG.debug(_("Reserving specific vlan %(vlan_id)s on physical "
                        "network %(physical_network)s from pool"), locals())
            state.allocated = True
        except exc.NoResultFound:
            LOG.debug(_("Reserving specific vlan %(vlan_id)s on physical "
                        "network %(physical_network)s outside pool"), locals())
            state = l2network_models_v2.NetworkState(physical_network, vlan_id)
            state.allocated = True
            session.add(state)


def release_network(session, physical_network, vlan_id, network_vlan_ranges):
    with session.begin(subtransactions=True):
        try:
            state = (session.query(l2network_models_v2.NetworkState).
                     filter_by(physical_network=physical_network,
                               vlan_id=vlan_id).
                     with_lockmode('update').
                     one())
            state.allocated = False
            inside = False
            for vlan_range in network_vlan_ranges.get(physical_network, []):
                if vlan_id >= vlan_range[0] and vlan_id <= vlan_range[1]:
                    inside = True
                    break
            if inside:
                LOG.debug(_("Releasing vlan %(vlan_id)s on physical network "
                            "%(physical_network)s to pool"),
                          locals())
            else:
                LOG.debug(_("Releasing vlan %(vlan_id)s on physical network "
                          "%(physical_network)s outside pool"), locals())
                session.delete(state)
        except exc.NoResultFound:
            LOG.warning(_("vlan_id %(vlan_id)s on physical network "
                          "%(physical_network)s not found"), locals())


def add_network_binding(session, network_id, physical_network, vlan_id):
    with session.begin(subtransactions=True):
        binding = l2network_models_v2.NetworkBinding(network_id,
                                                     physical_network, vlan_id)
        session.add(binding)


def get_network_binding(session, network_id):
    try:
        binding = (session.query(l2network_models_v2.NetworkBinding).
                   filter_by(network_id=network_id).
                   one())
        return binding
    except exc.NoResultFound:
        return


def get_port_from_device(device):
    """Get port from database"""
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
    plugin = manager.QuantumManager.get_plugin()
    port_dict = plugin._make_port_dict(port)
    port_dict['security_groups'] = []
    for port_in_db, sg_id in port_and_sgs:
        if sg_id:
            port_dict['security_groups'].append(sg_id)
    port_dict['security_group_rules'] = []
    port_dict['security_group_source_groups'] = []
    port_dict['fixed_ips'] = [ip['ip_address']
                              for ip in port['fixed_ips']]
    return port_dict


def set_port_status(port_id, status):
    """Set the port status"""
    LOG.debug(_("set_port_status as %s called"), status)
    session = db.get_session()
    try:
        port = session.query(models_v2.Port).filter_by(id=port_id).one()
        port['status'] = status
        session.merge(port)
        session.flush()
    except exc.NoResultFound:
        raise q_exc.PortNotFound(port_id=port_id)

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira, Inc.
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

from sqlalchemy.orm import exc

import neutron.db.api as db
from neutron.openstack.common.db import exception as d_exc
from neutron.openstack.common import log as logging
from neutron.plugins.nicira.dbexts import networkgw_db
from neutron.plugins.nicira.dbexts import nicira_models

LOG = logging.getLogger(__name__)


def get_network_bindings(session, network_id):
    session = session or db.get_session()
    return (session.query(nicira_models.NvpNetworkBinding).
            filter_by(network_id=network_id).
            all())


def get_network_bindings_by_vlanid(session, vlan_id):
    session = session or db.get_session()
    return (session.query(nicira_models.NvpNetworkBinding).
            filter_by(vlan_id=vlan_id).
            all())


def add_network_binding(session, network_id, binding_type, phy_uuid, vlan_id):
    with session.begin(subtransactions=True):
        binding = nicira_models.NvpNetworkBinding(network_id, binding_type,
                                                  phy_uuid, vlan_id)
        session.add(binding)
    return binding


def add_neutron_nsx_network_mapping(session, neutron_id, nsx_switch_id):
    with session.begin(subtransactions=True):
        mapping = nicira_models.NeutronNsxNetworkMapping(
            neutron_id=neutron_id, nsx_id=nsx_switch_id)
        session.add(mapping)
        return mapping


def add_neutron_nsx_port_mapping(session, neutron_id,
                                 nsx_switch_id, nsx_port_id):
    session.begin(subtransactions=True)
    try:
        mapping = nicira_models.NeutronNsxPortMapping(
            neutron_id, nsx_switch_id, nsx_port_id)
        session.add(mapping)
        session.commit()
    except d_exc.DBDuplicateEntry:
        session.rollback()
        # do not complain if the same exact mapping is being added, otherwise
        # re-raise because even though it is possible for the same neutron
        # port to map to different back-end ports over time, this should not
        # occur whilst a mapping already exists
        current = get_nsx_switch_and_port_id(session, neutron_id)
        if current[1] == nsx_port_id:
            LOG.debug(_("Port mapping for %s already available"), neutron_id)
        else:
            raise
    except d_exc.DBError:
        # rollback for any other db error
        session.rollback()
        raise
    return mapping


def add_neutron_nsx_router_mapping(session, neutron_id, nsx_router_id):
    with session.begin(subtransactions=True):
        mapping = nicira_models.NeutronNsxRouterMapping(
            neutron_id=neutron_id, nsx_id=nsx_router_id)
        session.add(mapping)
        return mapping


def get_nsx_switch_ids(session, neutron_id):
    # This function returns a list of NSX switch identifiers because of
    # the possibility of chained logical switches
    return [mapping['nsx_id'] for mapping in
            session.query(nicira_models.NeutronNsxNetworkMapping).filter_by(
                neutron_id=neutron_id)]


def get_nsx_switch_and_port_id(session, neutron_id):
    try:
        mapping = (session.query(nicira_models.NeutronNsxPortMapping).
                   filter_by(neutron_id=neutron_id).
                   one())
        return mapping['nsx_switch_id'], mapping['nsx_port_id']
    except exc.NoResultFound:
        LOG.debug(_("NSX identifiers for neutron port %s not yet "
                    "stored in Neutron DB"), neutron_id)
        return None, None


def get_nsx_router_id(session, neutron_id):
    try:
        mapping = (session.query(nicira_models.NeutronNsxRouterMapping).
                   filter_by(neutron_id=neutron_id).one())
        return mapping['nsx_id']
    except exc.NoResultFound:
        LOG.debug(_("NSX identifiers for neutron router %s not yet "
                    "stored in Neutron DB"), neutron_id)


def _delete_by_neutron_id(session, model, neutron_id):
    return session.query(model).filter_by(neutron_id=neutron_id).delete()


def delete_neutron_nsx_port_mapping(session, neutron_id):
    return _delete_by_neutron_id(
        session, nicira_models.NeutronNsxPortMapping, neutron_id)


def delete_neutron_nsx_router_mapping(session, neutron_id):
    return _delete_by_neutron_id(
        session, nicira_models.NeutronNsxRouterMapping, neutron_id)


def unset_default_network_gateways(session):
    with session.begin(subtransactions=True):
        session.query(networkgw_db.NetworkGateway).update(
            {networkgw_db.NetworkGateway.default: False})


def set_default_network_gateway(session, gw_id):
    with session.begin(subtransactions=True):
        gw = (session.query(networkgw_db.NetworkGateway).
              filter_by(id=gw_id).one())
        gw['default'] = True


def set_multiprovider_network(session, network_id):
    with session.begin(subtransactions=True):
        multiprovider_network = nicira_models.MultiProviderNetworks(
            network_id)
        session.add(multiprovider_network)
        return multiprovider_network


def is_multiprovider_network(session, network_id):
    with session.begin(subtransactions=True):
        return bool(
            session.query(nicira_models.MultiProviderNetworks).filter_by(
                network_id=network_id).first())

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
from neutron.openstack.common import log as logging
from neutron.plugins.nicira.dbexts import nicira_models
from neutron.plugins.nicira.dbexts import nicira_networkgw_db

LOG = logging.getLogger(__name__)


def get_network_binding(session, network_id):
    session = session or db.get_session()
    try:
        binding = (session.query(nicira_models.NvpNetworkBinding).
                   filter_by(network_id=network_id).
                   one())
        return binding
    except exc.NoResultFound:
        return


def get_network_binding_by_vlanid(session, vlan_id):
    session = session or db.get_session()
    try:
        binding = (session.query(nicira_models.NvpNetworkBinding).
                   filter_by(vlan_id=vlan_id).
                   one())
        return binding
    except exc.NoResultFound:
        return


def add_network_binding(session, network_id, binding_type, phy_uuid, vlan_id):
    with session.begin(subtransactions=True):
        binding = nicira_models.NvpNetworkBinding(network_id, binding_type,
                                                  phy_uuid, vlan_id)
        session.add(binding)
    return binding


def add_neutron_nvp_port_mapping(session, neutron_id, nvp_id):
    with session.begin(subtransactions=True):
        mapping = nicira_models.NeutronNvpPortMapping(neutron_id, nvp_id)
        session.add(mapping)
        return mapping


def get_nvp_port_id(session, neutron_id):
    try:
        mapping = (session.query(nicira_models.NeutronNvpPortMapping).
                   filter_by(quantum_id=neutron_id).
                   one())
        return mapping['nvp_id']
    except exc.NoResultFound:
        return


def delete_neutron_nvp_port_mapping(session, neutron_id):
    return (session.query(nicira_models.NeutronNvpPortMapping).
            filter_by(quantum_id=neutron_id).delete())


def unset_default_network_gateways(session):
    with session.begin(subtransactions=True):
        session.query(nicira_networkgw_db.NetworkGateway).update(
            {nicira_networkgw_db.NetworkGateway.default: False})


def set_default_network_gateway(session, gw_id):
    with session.begin(subtransactions=True):
        gw = (session.query(nicira_networkgw_db.NetworkGateway).
              filter_by(id=gw_id).one())
        gw['default'] = True

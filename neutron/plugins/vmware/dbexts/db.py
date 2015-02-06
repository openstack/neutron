# Copyright 2012 VMware, Inc.
#
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

from oslo_db import exception as db_exc
from oslo_utils import excutils
from sqlalchemy.orm import exc

import neutron.db.api as db
from neutron.openstack.common import log as logging
from neutron.plugins.vmware.dbexts import nsx_models

LOG = logging.getLogger(__name__)


def get_network_bindings(session, network_id):
    session = session or db.get_session()
    return (session.query(nsx_models.TzNetworkBinding).
            filter_by(network_id=network_id).
            all())


def get_network_bindings_by_vlanid_and_physical_net(session, vlan_id,
                                                    phy_uuid):
    session = session or db.get_session()
    return (session.query(nsx_models.TzNetworkBinding).
            filter_by(vlan_id=vlan_id, phy_uuid=phy_uuid).
            all())


def delete_network_bindings(session, network_id):
    return (session.query(nsx_models.TzNetworkBinding).
            filter_by(network_id=network_id).delete())


def add_network_binding(session, network_id, binding_type, phy_uuid, vlan_id):
    with session.begin(subtransactions=True):
        binding = nsx_models.TzNetworkBinding(network_id, binding_type,
                                          phy_uuid, vlan_id)
        session.add(binding)
    return binding


def add_neutron_nsx_network_mapping(session, neutron_id, nsx_switch_id):
    with session.begin(subtransactions=True):
        mapping = nsx_models.NeutronNsxNetworkMapping(
            neutron_id=neutron_id, nsx_id=nsx_switch_id)
        session.add(mapping)
        return mapping


def add_neutron_nsx_port_mapping(session, neutron_id,
                                 nsx_switch_id, nsx_port_id):
    session.begin(subtransactions=True)
    try:
        mapping = nsx_models.NeutronNsxPortMapping(
            neutron_id, nsx_switch_id, nsx_port_id)
        session.add(mapping)
        session.commit()
    except db_exc.DBDuplicateEntry:
        with excutils.save_and_reraise_exception() as ctxt:
            session.rollback()
            # do not complain if the same exact mapping is being added,
            # otherwise re-raise because even though it is possible for the
            # same neutron port to map to different back-end ports over time,
            # this should not occur whilst a mapping already exists
            current = get_nsx_switch_and_port_id(session, neutron_id)
            if current[1] == nsx_port_id:
                LOG.debug("Port mapping for %s already available",
                          neutron_id)
                ctxt.reraise = False
    except db_exc.DBError:
        with excutils.save_and_reraise_exception():
            # rollback for any other db error
            session.rollback()
    return mapping


def add_neutron_nsx_router_mapping(session, neutron_id, nsx_router_id):
    with session.begin(subtransactions=True):
        mapping = nsx_models.NeutronNsxRouterMapping(
            neutron_id=neutron_id, nsx_id=nsx_router_id)
        session.add(mapping)
        return mapping


def add_neutron_nsx_security_group_mapping(session, neutron_id, nsx_id):
    """Map a Neutron security group to a NSX security profile.

    :param session: a valid database session object
    :param neutron_id: a neutron security group identifier
    :param nsx_id: a nsx security profile identifier
    """
    with session.begin(subtransactions=True):
        mapping = nsx_models.NeutronNsxSecurityGroupMapping(
            neutron_id=neutron_id, nsx_id=nsx_id)
        session.add(mapping)
        return mapping


def get_nsx_switch_ids(session, neutron_id):
    # This function returns a list of NSX switch identifiers because of
    # the possibility of chained logical switches
    return [mapping['nsx_id'] for mapping in
            session.query(nsx_models.NeutronNsxNetworkMapping).filter_by(
                neutron_id=neutron_id)]


def get_nsx_switch_and_port_id(session, neutron_id):
    try:
        mapping = (session.query(nsx_models.NeutronNsxPortMapping).
                   filter_by(neutron_id=neutron_id).
                   one())
        return mapping['nsx_switch_id'], mapping['nsx_port_id']
    except exc.NoResultFound:
        LOG.debug("NSX identifiers for neutron port %s not yet "
                  "stored in Neutron DB", neutron_id)
        return None, None


def get_nsx_router_id(session, neutron_id):
    try:
        mapping = (session.query(nsx_models.NeutronNsxRouterMapping).
                   filter_by(neutron_id=neutron_id).one())
        return mapping['nsx_id']
    except exc.NoResultFound:
        LOG.debug("NSX identifiers for neutron router %s not yet "
                  "stored in Neutron DB", neutron_id)


def get_nsx_security_group_id(session, neutron_id):
    """Return the id of a security group in the NSX backend.

    Note: security groups are called 'security profiles' in NSX
    """
    try:
        mapping = (session.query(nsx_models.NeutronNsxSecurityGroupMapping).
                   filter_by(neutron_id=neutron_id).
                   one())
        return mapping['nsx_id']
    except exc.NoResultFound:
        LOG.debug("NSX identifiers for neutron security group %s not yet "
                  "stored in Neutron DB", neutron_id)
        return None


def _delete_by_neutron_id(session, model, neutron_id):
    return session.query(model).filter_by(neutron_id=neutron_id).delete()


def delete_neutron_nsx_port_mapping(session, neutron_id):
    return _delete_by_neutron_id(
        session, nsx_models.NeutronNsxPortMapping, neutron_id)


def delete_neutron_nsx_router_mapping(session, neutron_id):
    return _delete_by_neutron_id(
        session, nsx_models.NeutronNsxRouterMapping, neutron_id)


def unset_default_network_gateways(session):
    with session.begin(subtransactions=True):
        session.query(nsx_models.NetworkGateway).update(
            {nsx_models.NetworkGateway.default: False})


def set_default_network_gateway(session, gw_id):
    with session.begin(subtransactions=True):
        gw = (session.query(nsx_models.NetworkGateway).
              filter_by(id=gw_id).one())
        gw['default'] = True


def set_multiprovider_network(session, network_id):
    with session.begin(subtransactions=True):
        multiprovider_network = nsx_models.MultiProviderNetworks(
            network_id)
        session.add(multiprovider_network)
        return multiprovider_network


def is_multiprovider_network(session, network_id):
    with session.begin(subtransactions=True):
        return bool(
            session.query(nsx_models.MultiProviderNetworks).filter_by(
                network_id=network_id).first())

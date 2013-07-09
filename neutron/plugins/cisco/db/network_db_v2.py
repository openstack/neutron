# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012, Cisco Systems, Inc.
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
# @author: Rohit Agarwalla, Cisco Systems, Inc.

from sqlalchemy.orm import exc

from neutron.db import api as db
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.common import cisco_constants as const
from neutron.plugins.cisco.common import cisco_exceptions as c_exc
from neutron.plugins.cisco.db import network_models_v2
from neutron.plugins.openvswitch import ovs_models_v2


LOG = logging.getLogger(__name__)


def get_all_vlanids():
    """Gets all the vlanids."""
    LOG.debug(_("get_all_vlanids() called"))
    session = db.get_session()
    return session.query(network_models_v2.VlanID).all()


def is_vlanid_used(vlan_id):
    """Checks if a vlanid is in use."""
    LOG.debug(_("is_vlanid_used() called"))
    session = db.get_session()
    try:
        vlanid = (session.query(network_models_v2.VlanID).
                  filter_by(vlan_id=vlan_id).one())
        return vlanid["vlan_used"]
    except exc.NoResultFound:
        raise c_exc.VlanIDNotFound(vlan_id=vlan_id)


def release_vlanid(vlan_id):
    """Sets the vlanid state to be unused."""
    LOG.debug(_("release_vlanid() called"))
    session = db.get_session()
    try:
        vlanid = (session.query(network_models_v2.VlanID).
                  filter_by(vlan_id=vlan_id).one())
        vlanid["vlan_used"] = False
        session.merge(vlanid)
        session.flush()
        return vlanid["vlan_used"]
    except exc.NoResultFound:
        raise c_exc.VlanIDNotFound(vlan_id=vlan_id)


def delete_vlanid(vlan_id):
    """Deletes a vlanid entry from db."""
    LOG.debug(_("delete_vlanid() called"))
    session = db.get_session()
    try:
        vlanid = (session.query(network_models_v2.VlanID).
                  filter_by(vlan_id=vlan_id).one())
        session.delete(vlanid)
        session.flush()
        return vlanid
    except exc.NoResultFound:
        pass


def reserve_vlanid():
    """Reserves the first unused vlanid."""
    LOG.debug(_("reserve_vlanid() called"))
    session = db.get_session()
    try:
        rvlan = (session.query(network_models_v2.VlanID).
                 filter_by(vlan_used=False).first())
        if not rvlan:
            raise exc.NoResultFound
        rvlanid = (session.query(network_models_v2.VlanID).
                   filter_by(vlan_id=rvlan["vlan_id"]).one())
        rvlanid["vlan_used"] = True
        session.merge(rvlanid)
        session.flush()
        return rvlan["vlan_id"]
    except exc.NoResultFound:
        raise c_exc.VlanIDNotAvailable()


def get_all_vlanids_used():
    """Gets all the vlanids used."""
    LOG.debug(_("get_all_vlanids() called"))
    session = db.get_session()
    return (session.query(network_models_v2.VlanID).
            filter_by(vlan_used=True).all())


def get_all_qoss(tenant_id):
    """Lists all the qos to tenant associations."""
    LOG.debug(_("get_all_qoss() called"))
    session = db.get_session()
    return (session.query(network_models_v2.QoS).
            filter_by(tenant_id=tenant_id).all())


def get_qos(tenant_id, qos_id):
    """Lists the qos given a tenant_id and qos_id."""
    LOG.debug(_("get_qos() called"))
    session = db.get_session()
    try:
        qos = (session.query(network_models_v2.QoS).
               filter_by(tenant_id=tenant_id).
               filter_by(qos_id=qos_id).one())
        return qos
    except exc.NoResultFound:
        raise c_exc.QosNotFound(qos_id=qos_id,
                                tenant_id=tenant_id)


def add_qos(tenant_id, qos_name, qos_desc):
    """Adds a qos to tenant association."""
    LOG.debug(_("add_qos() called"))
    session = db.get_session()
    try:
        qos = (session.query(network_models_v2.QoS).
               filter_by(tenant_id=tenant_id).
               filter_by(qos_name=qos_name).one())
        raise c_exc.QosNameAlreadyExists(qos_name=qos_name,
                                         tenant_id=tenant_id)
    except exc.NoResultFound:
        qos = network_models_v2.QoS(tenant_id, qos_name, qos_desc)
        session.add(qos)
        session.flush()
        return qos


def remove_qos(tenant_id, qos_id):
    """Removes a qos to tenant association."""
    session = db.get_session()
    try:
        qos = (session.query(network_models_v2.QoS).
               filter_by(tenant_id=tenant_id).
               filter_by(qos_id=qos_id).one())
        session.delete(qos)
        session.flush()
        return qos
    except exc.NoResultFound:
        pass


def update_qos(tenant_id, qos_id, new_qos_name=None):
    """Updates a qos to tenant association."""
    session = db.get_session()
    try:
        qos = (session.query(network_models_v2.QoS).
               filter_by(tenant_id=tenant_id).
               filter_by(qos_id=qos_id).one())
        if new_qos_name:
            qos["qos_name"] = new_qos_name
        session.merge(qos)
        session.flush()
        return qos
    except exc.NoResultFound:
        raise c_exc.QosNotFound(qos_id=qos_id,
                                tenant_id=tenant_id)


def get_all_credentials(tenant_id):
    """Lists all the creds for a tenant."""
    session = db.get_session()
    return (session.query(network_models_v2.Credential).
            filter_by(tenant_id=tenant_id).all())


def get_credential(tenant_id, credential_id):
    """Lists the creds for given a cred_id and tenant_id."""
    session = db.get_session()
    try:
        cred = (session.query(network_models_v2.Credential).
                filter_by(tenant_id=tenant_id).
                filter_by(credential_id=credential_id).one())
        return cred
    except exc.NoResultFound:
        raise c_exc.CredentialNotFound(credential_id=credential_id,
                                       tenant_id=tenant_id)


def get_credential_name(tenant_id, credential_name):
    """Lists the creds for given a cred_name and tenant_id."""
    session = db.get_session()
    try:
        cred = (session.query(network_models_v2.Credential).
                filter_by(tenant_id=tenant_id).
                filter_by(credential_name=credential_name).one())
        return cred
    except exc.NoResultFound:
        raise c_exc.CredentialNameNotFound(credential_name=credential_name,
                                           tenant_id=tenant_id)


def add_credential(tenant_id, credential_name, user_name, password):
    """Adds a qos to tenant association."""
    session = db.get_session()
    try:
        cred = (session.query(network_models_v2.Credential).
                filter_by(tenant_id=tenant_id).
                filter_by(credential_name=credential_name).one())
        raise c_exc.CredentialAlreadyExists(credential_name=credential_name,
                                            tenant_id=tenant_id)
    except exc.NoResultFound:
        cred = network_models_v2.Credential(tenant_id, credential_name,
                                            user_name, password)
        session.add(cred)
        session.flush()
        return cred


def remove_credential(tenant_id, credential_id):
    """Removes a credential from a  tenant."""
    session = db.get_session()
    try:
        cred = (session.query(network_models_v2.Credential).
                filter_by(tenant_id=tenant_id).
                filter_by(credential_id=credential_id).one())
        session.delete(cred)
        session.flush()
        return cred
    except exc.NoResultFound:
        pass


def update_credential(tenant_id, credential_id,
                      new_user_name=None, new_password=None):
    """Updates a credential for a tenant."""
    session = db.get_session()
    try:
        cred = (session.query(network_models_v2.Credential).
                filter_by(tenant_id=tenant_id).
                filter_by(credential_id=credential_id).one())
        if new_user_name:
            cred["user_name"] = new_user_name
        if new_password:
            cred["password"] = new_password
        session.merge(cred)
        session.flush()
        return cred
    except exc.NoResultFound:
        raise c_exc.CredentialNotFound(credential_id=credential_id,
                                       tenant_id=tenant_id)


def add_provider_network(network_id, network_type, segmentation_id):
    """Add a network to the provider network table."""
    session = db.get_session()
    if session.query(network_models_v2.ProviderNetwork).filter_by(
            network_id=network_id).first():
        raise c_exc.ProviderNetworkExists(network_id)
    pnet = network_models_v2.ProviderNetwork(network_id=network_id,
                                             network_type=network_type,
                                             segmentation_id=segmentation_id)
    session.add(pnet)
    session.flush()


def remove_provider_network(network_id):
    """Remove network_id from the provider network table.

    :param network_id: Any network id. If it is not in the table, do nothing.
    :return: network_id if it was in the table and successfully removed.
    """
    session = db.get_session()
    pnet = (session.query(network_models_v2.ProviderNetwork).
            filter_by(network_id=network_id).first())
    if pnet:
        session.delete(pnet)
        session.flush()
        return network_id


def is_provider_network(network_id):
    """Return True if network_id is in the provider network table."""
    session = db.get_session()
    if session.query(network_models_v2.ProviderNetwork).filter_by(
            network_id=network_id).first():
        return True


def is_provider_vlan(vlan_id):
    """Check for a for a vlan provider network with the specified vland_id.

    Returns True if the provider network table contains a vlan network
    with the specified vlan_id.
    """
    session = db.get_session()
    if (session.query(network_models_v2.ProviderNetwork).
            filter_by(network_type=const.NETWORK_TYPE_VLAN,
                      segmentation_id=vlan_id).first()):
        return True


def get_ovs_vlans():
    session = db.get_session()
    bindings = (session.query(ovs_models_v2.VlanAllocation.vlan_id).
                filter_by(allocated=True))
    return [binding.vlan_id for binding in bindings]

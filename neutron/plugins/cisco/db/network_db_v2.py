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

from oslo_log import log as logging
from sqlalchemy.orm import exc

from neutron.db import api as db
from neutron.openstack.common import uuidutils
from neutron.plugins.cisco.common import cisco_constants as const
from neutron.plugins.cisco.common import cisco_exceptions as c_exc
from neutron.plugins.cisco.db import network_models_v2


LOG = logging.getLogger(__name__)


def get_all_qoss(tenant_id):
    """Lists all the qos to tenant associations."""
    LOG.debug("get_all_qoss() called")
    session = db.get_session()
    return (session.query(network_models_v2.QoS).
            filter_by(tenant_id=tenant_id).all())


def get_qos(tenant_id, qos_id):
    """Lists the qos given a tenant_id and qos_id."""
    LOG.debug("get_qos() called")
    session = db.get_session()
    try:
        return (session.query(network_models_v2.QoS).
                filter_by(tenant_id=tenant_id).
                filter_by(qos_id=qos_id).one())
    except exc.NoResultFound:
        raise c_exc.QosNotFound(qos_id=qos_id,
                                tenant_id=tenant_id)


def add_qos(tenant_id, qos_name, qos_desc):
    """Adds a qos to tenant association."""
    LOG.debug("add_qos() called")
    session = db.get_session()
    try:
        qos = (session.query(network_models_v2.QoS).
               filter_by(tenant_id=tenant_id).
               filter_by(qos_name=qos_name).one())
        raise c_exc.QosNameAlreadyExists(qos_name=qos_name,
                                         tenant_id=tenant_id)
    except exc.NoResultFound:
        qos = network_models_v2.QoS(qos_id=uuidutils.generate_uuid(),
                                    tenant_id=tenant_id,
                                    qos_name=qos_name,
                                    qos_desc=qos_desc)
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


def get_all_credentials():
    """Lists all the creds for a tenant."""
    session = db.get_session()
    return (session.query(network_models_v2.Credential).all())


def get_credential(credential_id):
    """Lists the creds for given a cred_id."""
    session = db.get_session()
    try:
        return (session.query(network_models_v2.Credential).
                filter_by(credential_id=credential_id).one())
    except exc.NoResultFound:
        raise c_exc.CredentialNotFound(credential_id=credential_id)


def get_credential_name(credential_name):
    """Lists the creds for given a cred_name."""
    session = db.get_session()
    try:
        return (session.query(network_models_v2.Credential).
                filter_by(credential_name=credential_name).one())
    except exc.NoResultFound:
        raise c_exc.CredentialNameNotFound(credential_name=credential_name)


def add_credential(credential_name, user_name, password, type):
    """Create a credential."""
    session = db.get_session()
    try:
        cred = (session.query(network_models_v2.Credential).
                filter_by(credential_name=credential_name).one())
        raise c_exc.CredentialAlreadyExists(credential_name=credential_name)
    except exc.NoResultFound:
        cred = network_models_v2.Credential(
            credential_id=uuidutils.generate_uuid(),
            credential_name=credential_name,
            user_name=user_name,
            password=password,
            type=type)
        session.add(cred)
        session.flush()
        return cred


def remove_credential(credential_id):
    """Removes a credential."""
    session = db.get_session()
    try:
        cred = (session.query(network_models_v2.Credential).
                filter_by(credential_id=credential_id).one())
        session.delete(cred)
        session.flush()
        return cred
    except exc.NoResultFound:
        pass


def update_credential(credential_id,
                      new_user_name=None, new_password=None):
    """Updates a credential for a tenant."""
    session = db.get_session()
    try:
        cred = (session.query(network_models_v2.Credential).
                filter_by(credential_id=credential_id).one())
        if new_user_name:
            cred["user_name"] = new_user_name
        if new_password:
            cred["password"] = new_password
        session.merge(cred)
        session.flush()
        return cred
    except exc.NoResultFound:
        raise c_exc.CredentialNotFound(credential_id=credential_id)


def get_all_n1kv_credentials():
    session = db.get_session()
    return (session.query(network_models_v2.Credential).
            filter_by(type='n1kv'))


def delete_all_n1kv_credentials():
    session = db.get_session()
    session.query(network_models_v2.Credential).filter_by(type='n1kv').delete()


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


class Credential_db_mixin(object):

    """Mixin class for Cisco Credentials as a resource."""

    def _make_credential_dict(self, credential, fields=None):
        res = {'credential_id': credential['credential_id'],
               'credential_name': credential['credential_name'],
               'user_name': credential['user_name'],
               'password': credential['password'],
               'type': credential['type']}
        return self._fields(res, fields)

    def create_credential(self, context, credential):
        """Create a credential."""
        c = credential['credential']
        cred = add_credential(c['credential_name'],
                              c['user_name'],
                              c['password'],
                              c['type'])
        return self._make_credential_dict(cred)

    def get_credentials(self, context, filters=None, fields=None):
        """Retrieve a list of credentials."""
        return self._get_collection(context,
                                    network_models_v2.Credential,
                                    self._make_credential_dict,
                                    filters=filters,
                                    fields=fields)

    def get_credential(self, context, id, fields=None):
        """Retireve the requested credential based on its id."""
        credential = get_credential(id)
        return self._make_credential_dict(credential, fields)

    def update_credential(self, context, id, credential):
        """Update a credential based on its id."""
        c = credential['credential']
        cred = update_credential(id,
                                 c['user_name'],
                                 c['password'])
        return self._make_credential_dict(cred)

    def delete_credential(self, context, id):
        """Delete a credential based on its id."""
        return remove_credential(id)

# Copyright (c) 2013 OpenStack Foundation
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
#

from sqlalchemy.orm import exc

from neutron.db import api as db
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.ml2.drivers.cisco.nexus import constants as const
from neutron.plugins.ml2.drivers.cisco.nexus import exceptions as c_exc
from neutron.plugins.ml2.drivers.cisco.nexus import network_models_v2
from neutron.plugins.ml2.drivers.cisco.nexus import nexus_models_v2  # noqa


LOG = logging.getLogger(__name__)


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
        cred = network_models_v2.Credential(
            credential_id=uuidutils.generate_uuid(),
            tenant_id=tenant_id,
            credential_name=credential_name,
            user_name=user_name,
            password=password)
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
            cred[const.CREDENTIAL_USERNAME] = new_user_name
        if new_password:
            cred[const.CREDENTIAL_PASSWORD] = new_password
        session.merge(cred)
        session.flush()
        return cred
    except exc.NoResultFound:
        raise c_exc.CredentialNotFound(credential_id=credential_id,
                                       tenant_id=tenant_id)

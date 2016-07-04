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

from oslo_db import exception as oslo_db_exception
from sqlalchemy.orm import exc as orm_exc

from neutron.common import exceptions as n_exc
from neutron.db import _utils as db_utils
from neutron.db.qos import models


def create_policy_network_binding(context, policy_id, network_id):
    try:
        with context.session.begin(subtransactions=True):
            db_obj = models.QosNetworkPolicyBinding(policy_id=policy_id,
                                                    network_id=network_id)
            context.session.add(db_obj)
    except oslo_db_exception.DBReferenceError:
        raise n_exc.NetworkQosBindingNotFound(net_id=network_id,
                                              policy_id=policy_id)


def delete_policy_network_binding(context, policy_id, network_id):
    try:
        with context.session.begin(subtransactions=True):
            db_object = (db_utils.model_query(context,
                                              models.QosNetworkPolicyBinding)
                         .filter_by(policy_id=policy_id,
                                    network_id=network_id).one())
            context.session.delete(db_object)
    except orm_exc.NoResultFound:
        raise n_exc.NetworkQosBindingNotFound(net_id=network_id,
                                              policy_id=policy_id)


def get_network_ids_by_network_policy_binding(context, policy_id):
    query = (db_utils.model_query(context, models.QosNetworkPolicyBinding)
            .filter_by(policy_id=policy_id).all())
    return [entry.network_id for entry in query]


def create_policy_port_binding(context, policy_id, port_id):
    try:
        with context.session.begin(subtransactions=True):
            db_obj = models.QosPortPolicyBinding(policy_id=policy_id,
                                                 port_id=port_id)
            context.session.add(db_obj)
    except oslo_db_exception.DBReferenceError:
        raise n_exc.PortQosBindingNotFound(port_id=port_id,
                                           policy_id=policy_id)


def delete_policy_port_binding(context, policy_id, port_id):
    try:
        with context.session.begin(subtransactions=True):
            db_object = (db_utils.model_query(context,
                                              models.QosPortPolicyBinding)
                         .filter_by(policy_id=policy_id,
                                    port_id=port_id).one())
            context.session.delete(db_object)
    except orm_exc.NoResultFound:
        raise n_exc.PortQosBindingNotFound(port_id=port_id,
                                           policy_id=policy_id)


def get_port_ids_by_port_policy_binding(context, policy_id):
    query = (db_utils.model_query(context, models.QosPortPolicyBinding)
            .filter_by(policy_id=policy_id).all())
    return [entry.port_id for entry in query]

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

from neutron.db import common_db_mixin as db
from neutron.db.qos import models


def create_policy_network_binding(context, policy_id, network_id):
    with context.session.begin(subtransactions=True):
        db_obj = models.QosNetworkPolicyBinding(policy_id=policy_id,
                                                network_id=network_id)
        context.session.add(db_obj)


def delete_policy_network_binding(context, policy_id, network_id):
    with context.session.begin(subtransactions=True):
        db_object = (db.model_query(context, models.QosNetworkPolicyBinding)
                     .filter_by(policy_id=policy_id,
                                network_id=network_id).one())
        context.session.delete(db_object)


def create_policy_port_binding(context, policy_id, port_id):
    with context.session.begin(subtransactions=True):
        db_obj = models.QosPortPolicyBinding(policy_id=policy_id,
                                             port_id=port_id)
        context.session.add(db_obj)


def delete_policy_port_binding(context, policy_id, port_id):
    with context.session.begin(subtransactions=True):
        db_object = (db.model_query(context, models.QosPortPolicyBinding)
                     .filter_by(policy_id=policy_id,
                                port_id=port_id).one())
        context.session.delete(db_object)

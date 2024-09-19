# Copyright 2017 Intel Corporation.
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

import abc

from neutron_lib.db import api as db_api
from neutron_lib.objects import common_types
import sqlalchemy as sa
from sqlalchemy import and_
from sqlalchemy import exists

from neutron.db.models import l3 as models_l3
from neutron.db import models_v2
from neutron.db.qos import models as qos_db_model
from neutron.objects import base


class _QosPolicyBindingMixin(metaclass=abc.ABCMeta):

    # must be set by the subclass
    _bound_model_id: sa.Column

    @classmethod
    def get_bound_ids(cls, context, policy_id):
        if not cls._bound_model_id:
            return []

        return cls.get_values(context, cls._bound_model_id.name,
                              policy_id=policy_id)


@base.NeutronObjectRegistry.register
class QosPolicyPortBinding(base.NeutronDbObject, _QosPolicyBindingMixin):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = qos_db_model.QosPortPolicyBinding

    fields = {
        'policy_id': common_types.UUIDField(),
        'port_id': common_types.UUIDField()
    }

    primary_keys = ['port_id']
    fields_no_update = ['policy_id', 'port_id']
    _bound_model_id = db_model.port_id

    @classmethod
    @db_api.CONTEXT_READER
    def get_ports_by_network_id(cls, context, network_id, policy_id=None):
        query = context.session.query(models_v2.Port).filter(
            models_v2.Port.network_id == network_id)
        if policy_id:
            query = query.filter(exists().where(and_(
                cls.db_model.port_id == models_v2.Port.id,
                cls.db_model.policy_id == policy_id)))
        else:
            query = query.filter(~exists().where(
                cls.db_model.port_id == models_v2.Port.id)).filter(
                    models_v2.Port.network_id == network_id)
        return query.all()


@base.NeutronObjectRegistry.register
class QosPolicyNetworkBinding(base.NeutronDbObject, _QosPolicyBindingMixin):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = qos_db_model.QosNetworkPolicyBinding

    fields = {
        'policy_id': common_types.UUIDField(),
        'network_id': common_types.UUIDField()
    }

    primary_keys = ['network_id']
    fields_no_update = ['policy_id', 'network_id']
    _bound_model_id = db_model.network_id


@base.NeutronObjectRegistry.register
class QosPolicyFloatingIPBinding(base.NeutronDbObject, _QosPolicyBindingMixin):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = qos_db_model.QosFIPPolicyBinding

    fields = {
        'policy_id': common_types.UUIDField(),
        'fip_id': common_types.UUIDField()
    }

    primary_keys = ['policy_id', 'fip_id']
    fields_no_update = ['policy_id', 'fip_id']
    _bound_model_id = db_model.fip_id

    @classmethod
    @db_api.CONTEXT_READER
    def get_fips_by_network_id(cls, context, network_id, policy_id=None):
        """Return the FIP belonging to a network, filtered by a QoS policy

        This method returns the floating IPs belonging to a network, with a
        QoS policy associated. If no QoS policy is passed, this method returns
        all floating IPs without any QoS policy associated.
        """
        query = context.session.query(models_l3.FloatingIP).filter(
            models_l3.FloatingIP.floating_network_id == network_id)
        if policy_id:
            query = query.filter(exists().where(and_(
                cls.db_model.fip_id == models_l3.FloatingIP.id,
                cls.db_model.policy_id == policy_id)))
        else:
            query = query.filter(~exists().where(
                cls.db_model.fip_id == models_l3.FloatingIP.id))
        return query.all()


@base.NeutronObjectRegistry.register
class QosPolicyRouterGatewayIPBinding(base.NeutronDbObject,
                                      _QosPolicyBindingMixin):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = qos_db_model.QosRouterGatewayIPPolicyBinding

    fields = {
        'policy_id': common_types.UUIDField(),
        'router_id': common_types.UUIDField()
    }

    primary_keys = ['policy_id', 'router_id']
    fields_no_update = ['policy_id', 'router_id']
    _bound_model_id = db_model.router_id

    @classmethod
    @db_api.CONTEXT_READER
    def get_routers_by_network_id(cls, context, network_id, policy_id=None):
        """Return the routers that have a network as GW, filtered by QoS policy

        This method returns the routers that have a gateway port on this
        network. If "policy_id" is defined, it will return those routers that
        have a gateway IP QoS policy associated. If "policy_id" is None, this
        method will return only those routers that doesn't have any gateway
        IP QoS policy associated.
        """
        query = context.session.query(models_l3.Router).filter(
            models_l3.Router.gw_port_id == models_v2.Port.id,
            models_v2.Port.network_id == network_id)
        if policy_id:
            query = query.filter(exists().where(and_(
                cls.db_model.router_id == models_l3.Router.id,
                cls.db_model.policy_id == policy_id)))
        else:
            query = query.filter(~exists().where(
                cls.db_model.router_id == models_l3.Router.id))
        return query.all()

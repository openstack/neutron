# Copyright (c) 2014 OpenStack Foundation.
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
# @author: Sumit Naiksatam

import datetime
import random

import netaddr
from oslo.config import cfg
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as q_exc
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import model_base
from neutron.db import models_v2
from neutron.db import sqlalchemyutils
from neutron import neutron_plugin_base_v2
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import timeutils
from neutron.openstack.common import uuidutils


LOG = logging.getLogger(__name__)


class Endpoint(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents an Endpoint consumed by the Group Policy."""
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))


class PortEndpoint(Endpoint):
    """Represents a Neutron port endpoint."""
    __tablename__ = 'gp_portendpoints'
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete='CASCADE'),
                        nullable=False,
                        unique=True)
    port = orm.relationship(models_v2.Port,
                            backref=orm.backref("gp_portendpoints",
                                                lazy='joined',
                                                uselist=False,
                                                cascade='delete'))
    epg_id = sa.Column(sa.String(36),
                       sa.ForeignKey('gp_portendpoints.id'),
                       nullable=True, unique=True)


class EndpointGroup(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents an Endpoint Group that is a collection of endpoints."""
    __tablename__ = 'gp_endpointgroups'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    port_endpoints = orm.relationship(PortEndpoint,
                                      backref='gp_endpointgroups')
    provided_contract_scopes = orm.relationship(ContractScope,
                                                backref='gp_endpointgroups')
    consumed_contract_scopes = orm.relationship(ContractScope,
                                                backref='gp_endpointgroups')


class ContractScope(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Models an EndpointGroup's provider/consumer relation to a Contract."""
    __tablename__ = 'gp_contractscopes'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    epg_id = sa.Column(sa.String(36),
                       sa.ForeignKey('gp_contractscopes.id'),
                       nullable=True, unique=True)
    contract_id = sa.Column(sa.String(36),
                            sa.ForeignKey('gp_contracts.id'))
    # TODO (Sumit): Add policy_label for scope


class ContractPolicyRuleAssociation(model_base.BASEV2):
    """Models the many to many relation between Contract and Policy rules."""
    __tablename__ = 'gp_contract_policyrule_associations'
    contract_id = sa.Column(sa.String(36),
                            sa.ForeignKey('gp_contracts.id'),
                            primary_key=True)
    policyrule_id = sa.Column(sa.String(36),
                              sa.ForeignKey('gp_policyrules.id'),
                              primary_key=True)


class PolicyRule(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Group Policy Rule."""
    __tablename__ = 'gp_policyrules'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    enabled = sa.Column(sa.Boolean)
    contracts = orm.relationship(ContractPolicyRuleAssociation,
                                 backref='gp_policyrules')
    # Default value would be Null implying both TCP and UDP
    # TODO (Sumit): Confirm this
    protocol = sa.Column(sa.Enum("tcp", "udp", name="protocol_type"),
                         nullable=True)
    port_range_min = sa.Column(sa.Integer)
    port_range_max = sa.Column(sa.Integer)
    action_type = sa.Column(sa.Enum('allow', 'redirect',
                                    name='gp_action_type'))
    # Default value would be Null when action_type is allow
    # however, value is required if something meaningful needs to be done
    # for redirect
    # TODO (Sumit): Revisit when other action_types are defined
    action_value = sa.Column(sa.String(36),
                             sa.ForeignKey('gp_contract_scopes.id'),
                             nullable=True, unique=True)
    # TODO (Sumit): Add policy_label


class Contract(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Contract that is a collection of Policy rules."""
    __tablename__ = 'gp_contracts'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    policy_rules = orm.relationship(ContractPolicyRuleAssociation,
                                    backref='gp_contract',
                                    lazy="joined")
    contract_scopes = orm.relationship(ContractScope,
                                       backref='gp_contract')


class DbMixin(neutron_plugin_base_v2.NeutronPluginBaseV2,
              db_base_plugin_v2.CommonDbMixin):
    """Group Policy plugin interface implementation using SQLAlchemy models.

    Whenever a non-read call happens the plugin will call an event handler
    class method (e.g., endpoint_created()).  The result is that this class
    can be sub-classed by other classes that add custom behaviors on certain
    events.
    """

    # This attribute specifies whether the plugin supports or not
    # bulk/pagination/sorting operations. Name mangling is used in
    # order to ensure it is qualified by class
    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    def __init__(self):
        db.configure_db()

    @classmethod
    def register_dict_extend_funcs(cls, resource, funcs):
        cur_funcs = cls._dict_extend_functions.get(resource, [])
        cur_funcs.extend(funcs)
        cls._dict_extend_functions[resource] = cur_funcs

    def _filter_non_model_columns(self, data, model):
        """Remove all the attributes from data which are not columns of
        the model passed as second parameter.
        """
        columns = [c.name for c in model.__table__.columns]
        return dict((k, v) for (k, v) in
                    data.iteritems() if k in columns)

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

import sqlalchemy as sa
from sqlalchemy.ext.orderinglist import ordering_list
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.common import exceptions as nexc
from neutron.common import log
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import group_policy as gpolicy
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants as const


LOG = logging.getLogger(__name__)


class Endpoint(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents an Endpoint consumed by the Group Policy."""
    __tablename__ = 'gp_endpoints'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    endpoint_group_id = sa.Column(sa.String(36),
                                  sa.ForeignKey('gp_endpoint_groups.id'),
                                  nullable=True, unique=True)


class ContractScope(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Models an EndpointGroup's provider/consumer relation to a Contract."""
    __tablename__ = 'gp_contract_scopes'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    scope_type = sa.Column(sa.Enum(const.GP_PROVIDES,
                                   const.GP_CONSUMES,
                                   name='scope_type'))
    endpoint_group_id = sa.Column(sa.String(36),
                                  sa.ForeignKey('gp_endpoint_groups.id'),
                                  nullable=True, unique=True)
    contract_id = sa.Column(sa.String(36),
                            sa.ForeignKey('gp_contracts.id'))
    # TODO(Sumit): Add policy_label for scope


class EndpointGroup(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents an Endpoint Group that is a collection of endpoints."""
    __tablename__ = 'gp_endpoint_groups'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    endpoints = orm.relationship(Endpoint, backref='gp_endpoint_groups')
    contract_scopes = orm.relationship(ContractScope,
                                       backref='gp_endpoint_groups')
    bridge_domain_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('gp_bridge_domains.id'),
                                 nullable=True, unique=True)


class ContractPolicyRuleAssociation(model_base.BASEV2):
    """Models the many to many relation between Contract and Policy rules."""
    __tablename__ = 'gp_contract_policyrule_associations'
    contract_id = sa.Column(sa.String(36),
                            sa.ForeignKey('gp_contracts.id'),
                            primary_key=True)
    policyrule_id = sa.Column(sa.String(36),
                              sa.ForeignKey('gp_policy_rules.id'),
                              primary_key=True)
    position = sa.Column(sa.Integer)


class PolicyRule(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Group Policy Rule."""
    __tablename__ = 'gp_policy_rules'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    enabled = sa.Column(sa.Boolean)
    contracts = orm.relationship(ContractPolicyRuleAssociation,
                                 backref='gp_policy_rules')


class PolicyClassifier(model_base.BASEV2, models_v2.HasId,
                       models_v2.HasTenant):
    """Represents a Group Policy Classifier."""
    __tablename__ = 'gp_policy_classifiers'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    # Default value would be Null implying all protocols
    # TODO(Sumit): Confirm this
    protocol = sa.Column(sa.Enum(const.TCP, const.UDP, const.ICMP,
                                 name="protocol_type"),
                         nullable=True)
    port_range_min = sa.Column(sa.Integer)
    port_range_max = sa.Column(sa.Integer)
    direction = sa.Column(sa.Enum(const.GP_DIRECTION_IN,
                                  const.GP_DIRECTION_OUT,
                                  const.GP_DIRECTION_BI,
                                  name='direction'))


class PolicyAction(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Group Policy Action."""
    __tablename__ = 'gp_policy_actions'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    action_type = sa.Column(sa.Enum(const.GP_ALLOW,
                                    const.GP_REDIRECT,
                                    name='action_type'))
    # Default action_value would be Null when action_type is allow
    # however, value is required if something meaningful needs to be done
    # for redirect
    # TODO(Sumit): Add foreign key constraints
    # TODO(Sumit): Revisit when other action_types are defined
    action_value = sa.Column(sa.String(36),
                             nullable=True, unique=True)


class Contract(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Contract that is a collection of Policy rules."""
    __tablename__ = 'gp_contracts'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    policy_rules = orm.relationship(ContractPolicyRuleAssociation,
                                    backref='gp_contract',
                                    lazy="joined",
                                    order_by=
                                    'ContractPolicyRuleAssociation.position',
                                    collection_class=
                                    ordering_list('position', count_from=1))
    contract_scopes = orm.relationship(ContractScope,
                                       backref='gp_contract')


class BridgeDomain(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents an Bridge Domain that is a collection of endpoint_groups."""
    __tablename__ = 'gp_bridge_domains'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    endpoint_groups = orm.relationship(EndpointGroup,
                                       backref='gp_bridge_domains')
    routing_domain_id = sa.Column(sa.String(36),
                                  sa.ForeignKey('gp_routing_domains.id'),
                                  nullable=True, unique=True)


class RoutingDomain(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents an Routing Domain with a non-overlapping IP address space."""
    __tablename__ = 'gp_routing_domains'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    ip_version = sa.Column(sa.Integer, nullable=False)
    ip_supernet = sa.Column(sa.String(64), nullable=False)
    subnet_prefix_length = sa.Column(sa.Integer, nullable=False)
    bridge_domains = orm.relationship(BridgeDomain,
                                      backref='gp_routing_domains')


class GroupPolicyDbMixin(gpolicy.GroupPolicyPluginBase,
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
    # TODO(Sumit): native bulk support
    __native_bulk_support = False
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

    def _get_endpoint(self, context, id):
        try:
            endpoint = self._get_by_id(context, Endpoint, id)
        except exc.NoResultFound:
            raise nexc.EndpointNotFound(endpoint_id=id)
        return endpoint

    def _get_endpoint_group(self, context, id):
        try:
            endpoint_group = self._get_by_id(context, EndpointGroup, id)
        except exc.NoResultFound:
            raise nexc.EndpointGroupNotFound(endpoint_group_id=id)
        return endpoint_group

    def _get_contract(self, context, id):
        try:
            contract = self._get_by_id(context, Contract, id)
        except exc.NoResultFound:
            raise nexc.ContractNotFound(contract_id=id)
        return contract

    def _get_contract_scope(self, context, id):
        try:
            contract_scope = self._get_by_id(context, ContractScope, id)
        except exc.NoResultFound:
            raise nexc.ContractScopeNotFound(contract_scope_id=id)
        return contract_scope

    def _get_policy_rule(self, context, id):
        try:
            policy_rule = self._get_by_id(context, PolicyRule, id)
        except exc.NoResultFound:
            raise nexc.PolicyRuleNotFound(policy_rule_id=id)
        return policy_rule

    def _get_policy_classifier(self, context, id):
        try:
            policy_classifier = self._get_by_id(context, PolicyClassifier, id)
        except exc.NoResultFound:
            raise nexc.PolicyClassifierNotFound(policy_classifier_id=id)
        return policy_classifier

    def _get_policy_action(self, context, id):
        try:
            policy_action = self._get_by_id(context, PolicyAction, id)
        except exc.NoResultFound:
            raise nexc.PolicyActionNotFound(policy_action_id=id)
        return policy_action

    def _get_bridge_domain(self, context, id):
        try:
            bridge_domain = self._get_by_id(context, BridgeDomain, id)
        except exc.NoResultFound:
            raise nexc.BridgeDomainNotFound(bridge_domain_id=id)
        return bridge_domain

    def _get_routing_domain(self, context, id):
        try:
            routing_domain = self._get_by_id(context, RoutingDomain, id)
        except exc.NoResultFound:
            raise nexc.RoutingDomainNotFound(routing_domain_id=id)
        return routing_domain

    def _get_min_max_ports_from_range(self, port_range):
        if not port_range:
            return [None, None]
        min_port, sep, max_port = port_range.partition(":")
        if not max_port:
            max_port = min_port
        return [int(min_port), int(max_port)]

    def _get_port_range_from_min_max_ports(self, min_port, max_port):
        if not min_port:
            return None
        if min_port == max_port:
            return str(min_port)
        else:
            return '%d:%d' % (min_port, max_port)

    def _make_endpoint_dict(self, ep, fields=None):
        res = {'id': ep['id'],
               'tenant_id': ep['tenant_id'],
               'name': ep['name'],
               'description': ep['description'],
               'endpoint_group_id': ep['endpoint_group_id']}
        return self._fields(res, fields)

    def _make_endpoint_group_dict(self, epg, fields=None):
        res = {'id': epg['id'],
               'tenant_id': epg['tenant_id'],
               'name': epg['name'],
               'description': epg['description'],
               'bridge_domain_id': epg['bridge_domain_id'],
               'endpoints': epg['endpoints']}
        # REVISIT(rkukura): Need to extract these from
        # epg['contract_scopes'].
        #
        # 'provided_contract_scopes': epg['provided_contract_scopes'],
        # 'consumed_contract_scopes': epg['consumed_contract_scopes']}
        return self._fields(res, fields)

    def _make_policy_classifier_dict(self, pc, fields=None):
        port_range = self._get_port_range_from_min_max_ports(
            pc['port_range_min'],
            pc['port_range_max'])
        res = {'id': pc['id'],
               'tenant_id': pc['tenant_id'],
               'name': pc['name'],
               'description': pc['description'],
               'protocol': pc['protocol'],
               'port_range': port_range,
               'direction': pc['direction']}
        return self._fields(res, fields)

    def _make_policy_action_dict(self, pa, fields=None):
        res = {'id': pa['id'],
               'tenant_id': pa['tenant_id'],
               'name': pa['name'],
               'description': pa['description'],
               'action_type': pa['action_type'],
               'action_value': pa['action_value']}
        return self._fields(res, fields)

    def _make_bridge_domain_dict(self, bd, fields=None):
        res = {'id': bd['id'],
               'tenant_id': bd['tenant_id'],
               'name': bd['name'],
               'description': bd['description'],
               'routing_domain_id': bd['routing_domain_id'],
               'endpoint_groups': bd['endpoint_groups']}
        return self._fields(res, fields)

    def _make_routing_domain_dict(self, rd, fields=None):
        res = {'id': rd['id'],
               'tenant_id': rd['tenant_id'],
               'name': rd['name'],
               'description': rd['description'],
               'ip_version': rd['ip_version'],
               'ip_supernet': rd['ip_supernet'],
               'subnet_prefix_length': rd['subnet_prefix_length'],
               'bridge_domains': rd['bridge_domains']}
        return self._fields(res, fields)

    @log.log
    def create_endpoint(self, context, endpoint):
        ep = endpoint['endpoint']
        tenant_id = self._get_tenant_id_for_create(context, ep)
        with context.session.begin(subtransactions=True):
            ep_db = Endpoint(id=uuidutils.generate_uuid(),
                             tenant_id=tenant_id,
                             name=ep['name'],
                             description=ep['description'],
                             endpoint_group_id=ep['endpoint_group_id'])
            context.session.add(ep_db)
        return self._make_endpoint_dict(ep_db)

    @log.log
    def update_endpoint(self, context, id, endpoint):
        ep = endpoint['endpoint']
        with context.session.begin(subtransactions=True):
            ep_query = context.session.query(
                Endpoint).with_lockmode('update')
            ep_db = ep_query.filter_by(id=id).one()
            ep_db.update(ep)
        return self._make_endpoint_dict(ep_db)

    @log.log
    def delete_endpoint(self, context, id):
        with context.session.begin(subtransactions=True):
            ep_query = context.session.query(
                Endpoint).with_lockmode('update')
            ep_db = ep_query.filter_by(id=id).one()
            context.session.delete(ep_db)

    @log.log
    def get_endpoint(self, context, id, fields=None):
        ep = self._get_endpoint(context, id)
        return self._make_endpoint_dict(ep, fields)

    @log.log
    def get_endpoints(self, context, filters=None, fields=None):
        return self._get_collection(context, Endpoint,
                                    self._make_endpoint_dict,
                                    filters=filters, fields=fields)

    @log.log
    def get_endpoints_count(self, context, filters=None):
        return self._get_collection_count(context, Endpoint,
                                          filters=filters)

    @log.log
    def create_endpoint_group(self, context, endpoint_group):
        epg = endpoint_group['endpoint_group']
        tenant_id = self._get_tenant_id_for_create(context, epg)
        with context.session.begin(subtransactions=True):
            epg_db = EndpointGroup(id=uuidutils.generate_uuid(),
                                   tenant_id=tenant_id,
                                   name=epg['name'],
                                   description=epg['description'],
                                   bridge_domain_id=epg['bridge_domain_id'])
            context.session.add(epg_db)
        return self._make_endpoint_group_dict(epg_db)

    @log.log
    def update_endpoint_group(self, context, id, endpoint_group):
        epg = endpoint_group['endpoint_group']
        with context.session.begin(subtransactions=True):
            epg_query = context.session.query(
                EndpointGroup).with_lockmode('update')
            epg_db = epg_query.filter_by(id=id).one()
            epg_db.update(epg)
        return self._make_endpoint_group_dict(epg_db)

    @log.log
    def delete_endpoint_group(self, context, id):
        with context.session.begin(subtransactions=True):
            epg_query = context.session.query(
                EndpointGroup).with_lockmode('update')
            epg_db = epg_query.filter_by(id=id).one()
            context.session.delete(epg_db)

    @log.log
    def get_endpoint_group(self, context, id, fields=None):
        epg = self._get_endpoint_group(context, id)
        return self._make_endpoint_group_dict(epg, fields)

    @log.log
    def get_endpoint_groups(self, context, filters=None, fields=None):
        return self._get_collection(context, EndpointGroup,
                                    self._make_endpoint_group_dict,
                                    filters=filters, fields=fields)

    @log.log
    def get_endpoint_groups_count(self, context, filters=None):
        return self._get_collection_count(context, EndpointGroup,
                                          filters=filters)

    @log.log
    def create_contract(self, context, contract):
        pass

    @log.log
    def update_contract(self, context, id, contract):
        pass

    @log.log
    def get_contracts(self, context, filters=None, fields=None):
        pass

    @log.log
    def get_contract(self, context, id, fields=None):
        pass

    @log.log
    def delete_contract(self, context, id):
        pass

    @log.log
    def create_contract_scope(self, context, contract_scope):
        pass

    @log.log
    def update_contract_scope(self, context, id, contract_scope):
        pass

    @log.log
    def get_contract_scopes(self, context, filters=None, fields=None):
        pass

    @log.log
    def get_contract_scope(self, context, id, fields=None):
        pass

    @log.log
    def delete_contract_scope(self, context, id):
        pass

    @log.log
    def get_policy_rules(self, context, filters=None, fields=None):
        pass

    @log.log
    def get_policy_rule(self, context, id, fields=None):
        pass

    @log.log
    def create_policy_rule(self, context, policy_rule):
        pass

    @log.log
    def update_policy_rule(self, context, id, policy_rule):
        pass

    @log.log
    def delete_policy_rule(self, context, id):
        pass

    @log.log
    def create_policy_classifier(self, context, policy_classifier):
        pc = policy_classifier['policy_classifier']
        tenant_id = self._get_tenant_id_for_create(context, pc)
        port_min, port_max = self._get_min_max_ports_from_range(
            pc['port_range'])
        with context.session.begin(subtransactions=True):
            pc_db = PolicyClassifier(id=uuidutils.generate_uuid(),
                                     tenant_id=tenant_id,
                                     name=pc['name'],
                                     description=pc['description'],
                                     protocol=pc['protocol'],
                                     port_range_min=port_min,
                                     port_range_max=port_max,
                                     direction=pc['direction'])
            context.session.add(pc_db)
        return self._make_policy_classifier_dict(pc_db)

    @log.log
    def update_policy_classifier(self, context, id, policy_classifier):
        pc = policy_classifier['policy_classifier']
        with context.session.begin(subtransactions=True):
            pc_query = context.session.query(
                PolicyClassifier).with_lockmode('update')
            pc_db = pc_query.filter_by(id=id).one()
            pc_db.update(pc)
        return self._make_policy_classifier_dict(pc_db)

    @log.log
    def delete_policy_classifier(self, context, id):
        with context.session.begin(subtransactions=True):
            pc_query = context.session.query(
                PolicyClassifier).with_lockmode('update')
            pc_db = pc_query.filter_by(id=id).one()
            context.session.delete(pc_db)

    @log.log
    def get_policy_classifier(self, context, id, fields=None):
        pc = self._get_policy_classifier(context, id)
        return self._make_policy_classifier_dict(pc, fields)

    @log.log
    def get_policy_classifiers(self, context, filters=None, fields=None):
        return self._get_collection(context, PolicyClassifier,
                                    self._make_policy_classifier_dict,
                                    filters=filters, fields=fields)

    @log.log
    def get_policy_classifiers_count(self, context, filters=None):
        return self._get_collection_count(context, PolicyClassifier,
                                          filters=filters)

    @log.log
    def create_policy_action(self, context, policy_action):
        pa = policy_action['policy_action']
        tenant_id = self._get_tenant_id_for_create(context, pa)
        with context.session.begin(subtransactions=True):
            pa_db = PolicyAction(id=uuidutils.generate_uuid(),
                                 tenant_id=tenant_id,
                                 name=pa['name'],
                                 description=pa['description'],
                                 action_type=pa['action_type'],
                                 action_value=pa['action_value'])
            context.session.add(pa_db)
        return self._make_policy_action_dict(pa_db)

    @log.log
    def update_policy_action(self, context, id, policy_action):
        pa = policy_action['policy_action']
        with context.session.begin(subtransactions=True):
            pa_query = context.session.query(
                PolicyAction).with_lockmode('update')
            pa_db = pa_query.filter_by(id=id).one()
            pa_db.update(pa)
        return self._make_policy_action_dict(pa_db)

    @log.log
    def delete_policy_action(self, context, id):
        with context.session.begin(subtransactions=True):
            pa_query = context.session.query(
                PolicyAction).with_lockmode('update')
            pa_db = pa_query.filter_by(id=id).one()
            context.session.delete(pa_db)

    @log.log
    def get_policy_action(self, context, id, fields=None):
        pa = self._get_policy_action(context, id)
        return self._make_policy_action_dict(pa, fields)

    @log.log
    def get_policy_actions(self, context, filters=None, fields=None):
        return self._get_collection(context, PolicyAction,
                                    self._make_policy_action_dict,
                                    filters=filters, fields=fields)

    @log.log
    def get_policy_actions_count(self, context, filters=None):
        return self._get_collection_count(context, PolicyAction,
                                          filters=filters)

    @log.log
    def create_bridge_domain(self, context, bridge_domain):
        bd = bridge_domain['bridge_domain']
        tenant_id = self._get_tenant_id_for_create(context, bd)
        with context.session.begin(subtransactions=True):
            bd_db = BridgeDomain(id=uuidutils.generate_uuid(),
                                 tenant_id=tenant_id,
                                 name=bd['name'],
                                 description=bd['description'],
                                 routing_domain_id=bd['routing_domain_id'])
            # TODO(Sumit): Process EPGs
            context.session.add(bd_db)
        return self._make_bridge_domain_dict(bd_db)

    @log.log
    def update_bridge_domain(self, context, id, bridge_domain):
        bd = bridge_domain['bridge_domain']
        with context.session.begin(subtransactions=True):
            bd_query = context.session.query(
                BridgeDomain).with_lockmode('update')
            bd_db = bd_query.filter_by(id=id).one()
            bd_db.update(bd)
        return self._make_bridge_domain_dict(bd_db)

    @log.log
    def delete_bridge_domain(self, context, id):
        with context.session.begin(subtransactions=True):
            bd_query = context.session.query(
                BridgeDomain).with_lockmode('update')
            bd_db = bd_query.filter_by(id=id).one()
            context.session.delete(bd_db)

    @log.log
    def get_bridge_domain(self, context, id, fields=None):
        bd = self._get_bridge_domain(context, id)
        return self._make_bridge_domain_dict(bd, fields)

    @log.log
    def get_bridge_domains(self, context, filters=None, fields=None):
        return self._get_collection(context, BridgeDomain,
                                    self._make_bridge_domain_dict,
                                    filters=filters, fields=fields)

    @log.log
    def get_bridge_domains_count(self, context, filters=None):
        return self._get_collection_count(context, BridgeDomain,
                                          filters=filters)

    @log.log
    def create_routing_domain(self, context, routing_domain):
        rd = routing_domain['routing_domain']
        tenant_id = self._get_tenant_id_for_create(context, rd)
        # TODO(Sumit): Check that subnet_prefix_length is smaller
        # than size of the supernet
        with context.session.begin(subtransactions=True):
            rd_db = RoutingDomain(id=uuidutils.generate_uuid(),
                                  tenant_id=tenant_id,
                                  name=rd['name'],
                                  description=rd['description'],
                                  ip_version=rd['ip_version'],
                                  ip_supernet=rd['ip_supernet'],
                                  subnet_prefix_length=
                                  rd['subnet_prefix_length'])
            context.session.add(rd_db)
        return self._make_routing_domain_dict(rd_db)

    @log.log
    def update_routing_domain(self, context, id, routing_domain):
        rd = routing_domain['routing_domain']
        # TODO(Sumit): Check that subnet_prefix_length is smaller
        # than size of the supernet if its being updated
        with context.session.begin(subtransactions=True):
            rd_query = context.session.query(
                RoutingDomain).with_lockmode('update')
            rd_db = rd_query.filter_by(id=id).one()
            rd_db.update(rd)
        return self._make_routing_domain_dict(rd_db)

    @log.log
    def delete_routing_domain(self, context, id):
        with context.session.begin(subtransactions=True):
            rd_query = context.session.query(
                RoutingDomain).with_lockmode('update')
            rd_db = rd_query.filter_by(id=id).one()
            context.session.delete(rd_db)

    @log.log
    def get_routing_domain(self, context, id, fields=None):
        rd = self._get_routing_domain(context, id)
        return self._make_routing_domain_dict(rd, fields)

    @log.log
    def get_routing_domains(self, context, filters=None, fields=None):
        return self._get_collection(context, RoutingDomain,
                                    self._make_routing_domain_dict,
                                    filters=filters, fields=fields)

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

import copy
import netaddr

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.common import log
from neutron.db.grouppolicy import db_group_policy as gpolicy_db
from neutron.db import l3_db  # noqa
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import group_policy as gpolicy
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils


LOG = logging.getLogger(__name__)


# Schema for extended group policy resource attributes map to Neutron contructs


class EndpointPortBinding(gpolicy_db.Endpoint):
    """Neutron port binding to an Endpoint."""
    __table_args__ = {'extend_existing': True}
    __mapper_args__ = {'polymorphic_identity': 'mapping'}
    # TODO(Sumit): confirm cascade constraints
    neutron_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'),
                                nullable=True, unique=True)
    neutron_port = orm.relationship(models_v2.Port,
                                    backref=orm.backref("gp_endpoint",
                                                        lazy='joined',
                                                        uselist=False))


class EndpointGroupSubnetAssociation(model_base.BASEV2):
    """Models the many to many relation between EndpointGroup and Subnets."""
    __tablename__ = 'gp_endpoint_group_subnet_associations'
    endpoint_group_id = sa.Column(sa.String(36),
                                  sa.ForeignKey('gp_endpoint_groups.id'),
                                  primary_key=True)
    neutron_subnet_id = sa.Column(sa.String(36),
                                  sa.ForeignKey('subnets.id'),
                                  primary_key=True)


class EndpointGroupSubnetBinding(gpolicy_db.EndpointGroup):
    """Neutron subnet binding to an EndpointGroup."""
    __table_args__ = {'extend_existing': True}
    __mapper_args__ = {'polymorphic_identity': 'mapping'}
    # TODO(Sumit): confirm cascade constraints
    neutron_subnets = orm.relationship(EndpointGroupSubnetAssociation,
                                       backref='gp_endpoint_groups',
                                       cascade='all', lazy="joined")


class BridgeDomainNetworkBinding(gpolicy_db.BridgeDomain):
    """Neutron network binding to a Bridgedomain."""
    __table_args__ = {'extend_existing': True}
    __mapper_args__ = {'polymorphic_identity': 'mapping'}
    # TODO(Sumit): confirm cascade constraints
    neutron_network_id = sa.Column(sa.String(36), sa.ForeignKey('networks.id'),
                                   nullable=True, unique=True)
    neutron_network = orm.relationship(models_v2.Network,
                                       backref=orm.backref("gp_bridge_domain",
                                                           lazy='joined',
                                                           uselist=False))


class RoutingDomainRouterAssociation(model_base.BASEV2):
    """Models the many to many relation between RoutingDomain and Routers."""
    __tablename__ = 'gp_routing_domain_router_associations'
    routing_domain_id = sa.Column(sa.String(36),
                                  sa.ForeignKey('gp_routing_domains.id'),
                                  primary_key=True)
    neutron_router_id = sa.Column(sa.String(36),
                                  sa.ForeignKey('routers.id'),
                                  primary_key=True)


class RoutingDomainRouterBinding(gpolicy_db.RoutingDomain):
    """Neutron router binding to an RouteringDomain."""
    __table_args__ = {'extend_existing': True}
    __mapper_args__ = {'polymorphic_identity': 'mapping'}
    # TODO(Sumit): confirm cascade constraints
    neutron_routers = orm.relationship(RoutingDomainRouterAssociation,
                                       backref='gp_routing_domains',
                                       lazy="joined")


class GroupPolicyMappingDbMixin(gpolicy_db.GroupPolicyDbMixin):
    """Group Policy Mapping interface implementation using SQLAlchemy models.

    Whenever a non-read call happens the plugin will call an event handler
    class method (e.g., endpoint_created()).  The result is that this class
    can be sub-classed by other classes that add custom behaviors on certain
    events.
    """

    def _get_endpoint(self, context, id):
        try:
            endpoint = self._get_by_id(context, EndpointPortBinding, id)
        except exc.NoResultFound:
            raise gpolicy.EndpointNotFound(endpoint_id=id)
        return endpoint

    def _get_endpoint_group(self, context, id):
        try:
            endpoint_group = self._get_by_id(context,
                                             EndpointGroupSubnetBinding, id)
        except exc.NoResultFound:
            raise gpolicy.EndpointGroupNotFound(endpoint_group_id=id)
        return endpoint_group

    def _get_bridge_domain(self, context, id):
        try:
            bridge_domain = self._get_by_id(context,
                                            BridgeDomainNetworkBinding, id)
        except exc.NoResultFound:
            raise gpolicy.BridgeDomainNotFound(bridge_domain_id=id)
        return bridge_domain

    def _get_routing_domain(self, context, id):
        try:
            routing_domain = self._get_by_id(context,
                                             RoutingDomainRouterBinding, id)
        except exc.NoResultFound:
            raise gpolicy.RoutingDomainNotFound(routing_domain_id=id)
        return routing_domain

    def _make_endpoint_dict(self, ep, fields=None):
        res = super(GroupPolicyMappingDbMixin,
                    self)._make_endpoint_dict(ep)
        res['neutron_port_id'] = ep['neutron_port_id']
        return self._fields(res, fields)

    def _make_endpoint_group_dict(self, epg, fields=None):
        res = super(GroupPolicyMappingDbMixin,
                    self)._make_endpoint_group_dict(epg)
        res['neutron_subnets'] = copy.copy(epg['neutron_subnets'])
        return self._fields(res, fields)

    def _make_bridge_domain_dict(self, bd, fields=None):
        res = super(GroupPolicyMappingDbMixin,
                    self)._make_bridge_domain_dict(bd)
        res['neutron_network_id'] = bd['neutron_network_id']
        return self._fields(res, fields)

    def _make_routing_domain_dict(self, rd, fields=None):
        res = super(GroupPolicyMappingDbMixin,
                    self)._make_routing_domain_dict(rd)
        res['neutron_routers'] = rd['neutron_routers']
        return self._fields(res, fields)

    def _set_network_for_bridge_domain(self, context, bd_id, network_id):
        with context.session.begin(subtransactions=True):
            bd_db = self._get_bridge_domain(context, bd_id)
            bd_db.neutron_network_id = network_id

    def _is_cidr_available_to_endpoint_group(self, context, epg_id, cidr):
        with context.session.begin(subtransactions=True):
            ipnet1 = netaddr.IPNetwork(cidr)
            # REVISIT(rkukura): Optimize querying for set of EPGs with
            # same RD?
            epg_db = self._get_endpoint_group(context, epg_id)
            rd_db = epg_db.bridge_domain.routing_domain
            for bd_db in rd_db.bridge_domains:
                for epg_db in bd_db.endpoint_groups:
                    for subnet in epg_db.neutron_subnets:
                        ipnet2 = netaddr.IPNetwork(subnet.cidr)
                        if (ipnet1.first <= ipnet2.last and
                            ipnet2.first <= ipnet1.last):
                            return False
        return True

    def _add_subnet_to_endpoint_group(self, context, epg_id, subnet_id):
        with context.session.begin(subtransactions=True):
            epg_db = self._get_endpoint_group(context, epg_id)
            assoc = EndpointGroupSubnetAssociation(endpoint_group_id=epg_id,
                                                   neutron_subnet_id=subnet_id)
            epg_db.neutron_subnets.append(assoc)
        # TODO(rkukura): Commit transaction (not subtransaction?) and
        # Raise exception if subnet overlaps any other subnets in
        # RD. Or come up with better way to atomically allocate
        # subnets from RD's supernet.
        return copy.copy(epg_db.neutron_subnets)

    @log.log
    def create_endpoint(self, context, endpoint):
        ep = endpoint['endpoint']
        tenant_id = self._get_tenant_id_for_create(context, ep)
        with context.session.begin(subtransactions=True):
            ep_db = EndpointPortBinding(id=uuidutils.generate_uuid(),
                                        tenant_id=tenant_id,
                                        name=ep['name'],
                                        description=ep['description'],
                                        endpoint_group_id=
                                        ep['endpoint_group_id'],
                                        neutron_port_id=ep['neutron_port_id'])
            context.session.add(ep_db)
        return self._make_endpoint_dict(ep_db)

    @log.log
    def create_endpoint_group(self, context, endpoint_group):
        epg = endpoint_group['endpoint_group']
        tenant_id = self._get_tenant_id_for_create(context, epg)
        with context.session.begin(subtransactions=True):
            epg_db = EndpointGroupSubnetBinding(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=epg['name'],
                description=epg['description'],
                bridge_domain_id=epg['bridge_domain_id'])
            # TODO(Sumit): Process subnets
            context.session.add(epg_db)
        return self._make_endpoint_group_dict(epg_db)

    @log.log
    def delete_endpoint_group(self, context, id):
        with context.session.begin(subtransactions=True):
            epg_query = context.session.query(
                EndpointGroupSubnetBinding).with_lockmode('update')
            epg_db = epg_query.filter_by(id=id).one()
            context.session.delete(epg_db)

    @log.log
    def create_bridge_domain(self, context, bridge_domain):
        bd = bridge_domain['bridge_domain']
        tenant_id = self._get_tenant_id_for_create(context, bd)
        with context.session.begin(subtransactions=True):
            bd_db = BridgeDomainNetworkBinding(id=uuidutils.generate_uuid(),
                                               tenant_id=tenant_id,
                                               name=bd['name'],
                                               description=bd['description'],
                                               routing_domain_id=
                                               bd['routing_domain_id'],
                                               neutron_network_id=
                                               bd['neutron_network_id'])
            context.session.add(bd_db)
        return self._make_bridge_domain_dict(bd_db)

    @log.log
    def create_routing_domain(self, context, routing_domain):
        rd = routing_domain['routing_domain']
        tenant_id = self._get_tenant_id_for_create(context, rd)
        with context.session.begin(subtransactions=True):
            rd_db = RoutingDomainRouterBinding(id=uuidutils.generate_uuid(),
                                               tenant_id=tenant_id,
                                               name=rd['name'],
                                               ip_version=rd['ip_version'],
                                               ip_supernet=rd['ip_supernet'],
                                               subnet_prefix_length=
                                               rd['subnet_prefix_length'],
                                               description=rd['description'])
            # TODO(Sumit): Process routers
            context.session.add(rd_db)
        return self._make_routing_domain_dict(rd_db)

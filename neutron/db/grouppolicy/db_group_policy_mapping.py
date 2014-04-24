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
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.common import exceptions as nexc
from neutron.common import log
from neutron.db.grouppolicy import db_group_policy as gpolicy_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils


LOG = logging.getLogger(__name__)


# Schema for extended group policy resource attributes map to Neutron contructs


class EndpointPortBinding(gpolicy_db.Endpoint):
    """Neutron port binding to an Endpoint."""
    __table_args__ = {'extend_existing': True}
    # TODO(Sumit): confirm cascade constraints
    neutron_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'),
                                nullable=True, unique=True)
    neutron_port = orm.relationship(models_v2.Port,
                                    backref=orm.backref("gp_endpoints",
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
    # TODO(Sumit): confirm cascade constraints
    neutron_subnets = orm.relationship(EndpointGroupSubnetAssociation,
                                       backref='gp_endpoint_groups',
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
            raise nexc.EndpointNotFound(endpoint_id=id)
        return endpoint

    def _get_endpoint_group(self, context, id):
        try:
            endpoint_group = self._get_by_id(context,
                                             EndpointGroupSubnetBinding, id)
        except exc.NoResultFound:
            raise nexc.EndpointGroupNotFound(endpoint_group_id=id)
        return endpoint_group

    def _make_endpoint_dict(self, ep, fields=None):
        res = super(GroupPolicyMappingDbMixin,
                    self)._make_endpoint_dict(ep)
        res['neutron_port_id'] = ep['neutron_port_id']
        return self._fields(res, fields)

    def _make_endpoint_group_dict(self, epg, fields=None):
        res = super(GroupPolicyMappingDbMixin,
                    self)._make_endpoint_group_dict(epg)
        res['neutron_subnets'] = epg['neutron_subnets']
        return self._fields(res, fields)

    @log.log
    def create_endpoint(self, context, endpoint):
        ep = endpoint['endpoint']
        tenant_id = self._get_tenant_id_for_create(context, ep)
        with context.session.begin(subtransactions=True):
            ep_db = EndpointPortBinding(id=uuidutils.generate_uuid(),
                                        tenant_id=tenant_id,
                                        name=ep['name'],
                                        description=ep['description'],
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
                description=epg['description'])
            # TODO(Sumit): Subnet processing
            context.session.add(epg_db)
        return self._make_endpoint_group_dict(epg_db)

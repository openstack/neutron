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

from neutron.db.grouppolicy import db_group_policy as gpolicy_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import group_policy as gpolicy
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


# Schema for extended group policy resource attributes map to Neutron contructs


class EndpointPortBinding(gpolicy_db.Endpoint):
    """Neutron port binding to an Endpoint."""
    __table_args__ = {'extend_existing': True}
    # TODO(Sumit): confirm cascade constraints
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id'), nullable=False, unique=True)
    port = orm.relationship(models_v2.Port,
                            backref=orm.backref("gp_endpoints", lazy='joined',
                                                uselist=False))


class EndpointGroupNetworkBinding(gpolicy_db.EndpointGroup):
    """Neutron network binding to an EndpointGroup."""
    __table_args__ = {'extend_existing': True}
    # TODO(Sumit): confirm cascade constraints
    network_id = sa.Column(sa.String(36), sa.ForeignKey('networks.id'),
                           nullable=False, unique=True)
    network = orm.relationship(models_v2.Network,
                               backref=orm.backref("gp_endpoint_groups",
                                                   lazy='joined',
                                                   uselist=False))


class GroupPolicyMappingDbMixin(gpolicy_db.GroupPolicyDbMixin):
    """Group Policy Mapping interface implementation using SQLAlchemy models.

    Whenever a non-read call happens the plugin will call an event handler
    class method (e.g., endpoint_created()).  The result is that this class
    can be sub-classed by other classes that add custom behaviors on certain
    events.
    """

    def _extend_endpoint_dict_portbinding(self, endpoint_res, endpoint_db):
        endpoint_res['neutron_port_id'] = endpoint_db['port_id']

    def _extend_endpoint_group_dict_networkbinding(self,
                                                   endpoint_group_res,
                                                   endpoint_group_db):
        endpoint_group_res['neutron_network_id'] = endpoint_group_db[
            'network_id']

    gpolicy_db.GroupPolicyDbMixin.register_dict_extend_funcs(
        gpolicy.ENDPOINTS, ['_extend_endpoint_dict_portbinding'])

    gpolicy_db.GroupPolicyDbMixin.register_dict_extend_funcs(
        gpolicy.ENDPOINT_GROUPS,
        ['_extend_endpoint_group_dict_networkbinding'])

# Copyright 2014 Alcatel-Lucent USA Inc.
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

from neutron.db import model_base
from neutron.db import models_v2


class NetPartition(model_base.BASEV2, models_v2.HasId):
    __tablename__ = 'nuage_net_partitions'
    name = sa.Column(sa.String(64))
    l3dom_tmplt_id = sa.Column(sa.String(36))
    l2dom_tmplt_id = sa.Column(sa.String(36))
    isolated_zone = sa.Column(sa.String(64))
    shared_zone = sa.Column(sa.String(64))


class NetPartitionRouter(model_base.BASEV2):
    __tablename__ = "nuage_net_partition_router_mapping"
    net_partition_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('nuage_net_partitions.id',
                                 ondelete="CASCADE"),
                                 primary_key=True)
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          primary_key=True)
    nuage_router_id = sa.Column(sa.String(36), unique=True)
    nuage_rtr_rt = sa.Column(sa.String(36))
    nuage_rtr_rd = sa.Column(sa.String(36))


class ProviderNetBinding(model_base.BASEV2):
    """Represents binding of virtual network to physical_network and vlan."""
    __tablename__ = 'nuage_provider_net_bindings'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    network_type = sa.Column(sa.String(32), nullable=False)
    physical_network = sa.Column(sa.String(64), nullable=False)
    vlan_id = sa.Column(sa.Integer, nullable=False)

    network = orm.relationship(
        models_v2.Network,
        backref=orm.backref("pnetbinding", lazy='joined',
                            uselist=False, cascade='delete'))


class SubnetL2Domain(model_base.BASEV2):
    __tablename__ = 'nuage_subnet_l2dom_mapping'
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id', ondelete="CASCADE"),
                          primary_key=True)
    net_partition_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('nuage_net_partitions.id',
                                 ondelete="CASCADE"))
    nuage_subnet_id = sa.Column(sa.String(36), unique=True)
    nuage_l2dom_tmplt_id = sa.Column(sa.String(36))
    nuage_user_id = sa.Column(sa.String(36))
    nuage_group_id = sa.Column(sa.String(36))
    nuage_managed_subnet = sa.Column(sa.Boolean())

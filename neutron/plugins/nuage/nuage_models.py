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
#
# @author: Ronak Shah, Nuage Networks, Alcatel-Lucent USA Inc.

from sqlalchemy import Boolean, Column, ForeignKey, String

from neutron.db import model_base
from neutron.db import models_v2


class NetPartition(model_base.BASEV2, models_v2.HasId):
    __tablename__ = 'net_partitions'
    name = Column(String(64))
    l3dom_tmplt_id = Column(String(36))
    l2dom_tmplt_id = Column(String(36))


class NetPartitionRouter(model_base.BASEV2):
    __tablename__ = "net_partition_router_mapping"
    net_partition_id = Column(String(36),
                              ForeignKey('net_partitions.id',
                                         ondelete="CASCADE"),
                              primary_key=True)
    router_id = Column(String(36),
                       ForeignKey('routers.id', ondelete="CASCADE"),
                       primary_key=True)
    nuage_router_id = Column(String(36))


class RouterZone(model_base.BASEV2):
    __tablename__ = "router_zone_mapping"
    router_id = Column(String(36),
                       ForeignKey('routers.id', ondelete="CASCADE"),
                       primary_key=True)
    nuage_zone_id = Column(String(36))
    nuage_user_id = Column(String(36))
    nuage_group_id = Column(String(36))


class SubnetL2Domain(model_base.BASEV2):
    __tablename__ = 'subnet_l2dom_mapping'
    subnet_id = Column(String(36),
                       ForeignKey('subnets.id', ondelete="CASCADE"),
                       primary_key=True)
    net_partition_id = Column(String(36),
                              ForeignKey('net_partitions.id',
                                         ondelete="CASCADE"))
    nuage_subnet_id = Column(String(36))
    nuage_l2dom_tmplt_id = Column(String(36))
    nuage_user_id = Column(String(36))
    nuage_group_id = Column(String(36))


class PortVPortMapping(model_base.BASEV2):
    __tablename__ = 'port_mapping'
    port_id = Column(String(36),
                     ForeignKey('ports.id', ondelete="CASCADE"),
                     primary_key=True)
    nuage_vport_id = Column(String(36))
    nuage_vif_id = Column(String(36))
    static_ip = Column(Boolean())

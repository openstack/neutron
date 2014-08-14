# Copyright 2014 Alcatel-Lucent USA Inc.
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

from neutron.db import common_db_mixin
from neutron.plugins.nuage import nuage_models


def add_net_partition(session, netpart_id,
                      l3dom_id, l2dom_id,
                      ent_name):
    net_partitioninst = nuage_models.NetPartition(id=netpart_id,
                                                  name=ent_name,
                                                  l3dom_tmplt_id=l3dom_id,
                                                  l2dom_tmplt_id=l2dom_id)
    session.add(net_partitioninst)
    return net_partitioninst


def delete_net_partition(session, net_partition):
    session.delete(net_partition)


def get_net_partition_by_name(session, name):
    query = session.query(nuage_models.NetPartition)
    return query.filter_by(name=name).first()


def get_net_partition_by_id(session, id):
    query = session.query(nuage_models.NetPartition)
    return query.filter_by(id=id).first()


def get_net_partitions(session, filters=None, fields=None):
    query = session.query(nuage_models.NetPartition)
    common_db = common_db_mixin.CommonDbMixin()
    query = common_db._apply_filters_to_query(query,
                                              nuage_models.NetPartition,
                                              filters)
    return query


def add_entrouter_mapping(session, np_id,
                          router_id,
                          n_l3id):
    ent_rtr_mapping = nuage_models.NetPartitionRouter(net_partition_id=np_id,
                                                      router_id=router_id,
                                                      nuage_router_id=n_l3id)
    session.add(ent_rtr_mapping)


def add_subnetl2dom_mapping(session, neutron_subnet_id,
                            nuage_sub_id,
                            np_id,
                            l2dom_id=None,
                            nuage_user_id=None,
                            nuage_group_id=None):
    subnet_l2dom = nuage_models.SubnetL2Domain(subnet_id=neutron_subnet_id,
                                               nuage_subnet_id=nuage_sub_id,
                                               net_partition_id=np_id,
                                               nuage_l2dom_tmplt_id=l2dom_id,
                                               nuage_user_id=nuage_user_id,
                                               nuage_group_id=nuage_group_id)
    session.add(subnet_l2dom)


def update_subnetl2dom_mapping(subnet_l2dom,
                               new_dict):
    subnet_l2dom.update(new_dict)


def delete_subnetl2dom_mapping(session, subnet_l2dom):
    session.delete(subnet_l2dom)


def get_subnet_l2dom_by_id(session, id):
    query = session.query(nuage_models.SubnetL2Domain)
    return query.filter_by(subnet_id=id).first()


def get_ent_rtr_mapping_by_entid(session,
                                 entid):
    query = session.query(nuage_models.NetPartitionRouter)
    return query.filter_by(net_partition_id=entid).all()


def get_ent_rtr_mapping_by_rtrid(session, rtrid):
    query = session.query(nuage_models.NetPartitionRouter)
    return query.filter_by(router_id=rtrid).first()


def add_network_binding(session, network_id, network_type, physical_network,
                        vlan_id):
    binding = nuage_models.ProviderNetBinding(
                            network_id=network_id,
                            network_type=network_type,
                            physical_network=physical_network,
                            vlan_id=vlan_id)
    session.add(binding)


def get_network_binding(session, network_id):
    return (session.query(nuage_models.ProviderNetBinding).
            filter_by(network_id=network_id).
            first())

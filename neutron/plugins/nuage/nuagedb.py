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

from neutron.db import db_base_plugin_v2
from neutron.plugins.nuage import nuage_models


def add_entrouter_mapping(session, np_id,
                          router_id,
                          n_l3id):
    ent_rtr_mapping = nuage_models.NetPartitionRouter(net_partition_id=np_id,
                                                      router_id=router_id,
                                                      nuage_router_id=n_l3id)
    session.add(ent_rtr_mapping)


def add_rtrzone_mapping(session, neutron_router_id,
                        nuage_zone_id,
                        nuage_user_id=None,
                        nuage_group_id=None):
    rtr_zone_mapping = nuage_models.RouterZone(router_id=neutron_router_id,
                                               nuage_zone_id=nuage_zone_id,
                                               nuage_user_id=nuage_user_id,
                                               nuage_group_id=nuage_group_id)
    session.add(rtr_zone_mapping)


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


def add_port_vport_mapping(session, port_id, nuage_vport_id,
                           nuage_vif_id, static_ip):
    port_mapping = nuage_models.PortVPortMapping(port_id=port_id,
                                                 nuage_vport_id=nuage_vport_id,
                                                 nuage_vif_id=nuage_vif_id,
                                                 static_ip=static_ip)
    session.add(port_mapping)
    return port_mapping


def update_port_vport_mapping(port_mapping,
                              new_dict):
    port_mapping.update(new_dict)


def get_port_mapping_by_id(session, id):
    query = session.query(nuage_models.PortVPortMapping)
    return query.filter_by(port_id=id).first()


def get_ent_rtr_mapping_by_rtrid(session, rtrid):
    query = session.query(nuage_models.NetPartitionRouter)
    return query.filter_by(router_id=rtrid).first()


def get_rtr_zone_mapping(session, router_id):
    query = session.query(nuage_models.RouterZone)
    return query.filter_by(router_id=router_id).first()


def get_subnet_l2dom_by_id(session, id):
    query = session.query(nuage_models.SubnetL2Domain)
    return query.filter_by(subnet_id=id).first()


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


def get_ent_rtr_mapping_by_entid(session,
                                 entid):
    query = session.query(nuage_models.NetPartitionRouter)
    return query.filter_by(net_partition_id=entid).all()


def get_net_partition_by_name(session, name):
    query = session.query(nuage_models.NetPartition)
    return query.filter_by(name=name).first()


def get_net_partition_by_id(session, id):
    query = session.query(nuage_models.NetPartition)
    return query.filter_by(id=id).first()


def get_net_partitions(session, filters=None, fields=None):
    query = session.query(nuage_models.NetPartition)
    common_db = db_base_plugin_v2.CommonDbMixin()
    query = common_db._apply_filters_to_query(query,
                                              nuage_models.NetPartition,
                                              filters)
    return query

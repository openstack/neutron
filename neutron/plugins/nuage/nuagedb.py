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

from neutron.db import common_db_mixin
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.db import securitygroups_db
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


def delete_net_partition_by_id(session, netpart_id):
    query = session.query(nuage_models.NetPartition)
    query.filter_by(id=netpart_id).delete()


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


def get_net_partition_ids(session):
    query = session.query(nuage_models.NetPartition.id)
    return [netpart[0] for netpart in query]


def get_net_partition_with_lock(session, netpart_id):
    query = session.query(nuage_models.NetPartition)
    netpart_db = query.filter_by(id=netpart_id).with_lockmode('update').one()
    return make_net_partition_dict(netpart_db)


def get_subnet_ids(session):
    query = session.query(models_v2.Subnet.id)
    return [subn[0] for subn in query]


def get_subnet_with_lock(session, sub_id):
    query = session.query(models_v2.Subnet)
    subnet_db = query.filter_by(id=sub_id).with_lockmode('update').one()
    return subnet_db


def get_router_ids(session):
    query = session.query(l3_db.Router.id)
    return [router[0] for router in query]


def get_router_with_lock(session, router_id):
    query = session.query(l3_db.Router)
    router_db = query.filter_by(id=router_id).with_lockmode('update').one()
    return router_db


def get_secgrp_ids(session):
    query = session.query(securitygroups_db.SecurityGroup.id)
    return [secgrp[0] for secgrp in query]


def get_secgrp_with_lock(session, secgrp_id):
    query = session.query(securitygroups_db.SecurityGroup)
    secgrp_db = query.filter_by(id=secgrp_id).with_lockmode('update').one()
    return secgrp_db


def get_secgrprule_ids(session):
    query = session.query(securitygroups_db.SecurityGroupRule.id)
    return [secgrprule[0] for secgrprule in query]


def get_secgrprule_with_lock(session, secgrprule_id):
    query = session.query(securitygroups_db.SecurityGroupRule)
    secgrprule_db = (query.filter_by(id=secgrprule_id).with_lockmode(
        'update').one())
    return secgrprule_db


def get_port_with_lock(session, port_id):
    query = session.query(models_v2.Port)
    port_db = query.filter_by(id=port_id).with_lockmode('update').one()
    return port_db


def get_fip_with_lock(session, fip_id):
    query = session.query(l3_db.FloatingIP)
    fip_db = query.filter_by(id=fip_id).with_lockmode('update').one()
    return fip_db


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


def get_update_subnetl2dom_mapping(session, new_dict):
    subnet_l2dom = get_subnet_l2dom_with_lock(session, new_dict['subnet_id'])
    subnet_l2dom.update(new_dict)


def update_entrtr_mapping(ent_rtr, new_dict):
    ent_rtr.update(new_dict)


def get_update_entrtr_mapping(session, new_dict):
    ent_rtr = get_ent_rtr_mapping_with_lock(session, new_dict['router_id'])
    ent_rtr.update(new_dict)


def delete_subnetl2dom_mapping(session, subnet_l2dom):
    session.delete(subnet_l2dom)


def get_subnet_l2dom_by_id(session, id):
    query = session.query(nuage_models.SubnetL2Domain)
    return query.filter_by(subnet_id=id).first()


def get_subnet_l2dom_with_lock(session, id):
    query = session.query(nuage_models.SubnetL2Domain)
    subl2dom = query.filter_by(subnet_id=id).with_lockmode('update').one()
    return subl2dom


def get_ent_rtr_mapping_by_entid(session, entid):
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
    return binding


def get_network_binding(session, network_id):
    return (session.query(nuage_models.ProviderNetBinding).
            filter_by(network_id=network_id).
            first())


def get_ent_rtr_mapping_with_lock(session, rtrid):
    query = session.query(nuage_models.NetPartitionRouter)
    entrtr = query.filter_by(router_id=rtrid).with_lockmode('update').one()
    return entrtr


def get_ipalloc_for_fip(session, network_id, ip, lock=False):
    query = session.query(models_v2.IPAllocation)
    if lock:
        # Lock is required when the resource is synced
        ipalloc_db = (query.filter_by(network_id=network_id).filter_by(
            ip_address=ip).with_lockmode('update').one())
    else:
        ipalloc_db = (query.filter_by(network_id=network_id).filter_by(
            ip_address=ip).one())
    return make_ipalloc_dict(ipalloc_db)


def get_all_net_partitions(session):
    net_partitions = get_net_partitions(session)
    return make_net_partition_list(net_partitions)


def get_all_routes(session):
    routes = session.query(extraroute_db.RouterRoute)
    return make_route_list(routes)


def get_route_with_lock(session, dest, nhop):
    query = session.query(extraroute_db.RouterRoute)
    route_db = (query.filter_by(destination=dest).filter_by(nexthop=nhop)
                .with_lockmode('update').one())
    return make_route_dict(route_db)


def make_ipalloc_dict(subnet_db):
    return {'port_id': subnet_db['port_id'],
            'subnet_id': subnet_db['subnet_id'],
            'network_id': subnet_db['network_id'],
            'ip_address': subnet_db['ip_address']}


def make_net_partition_dict(net_partition):
    return {'id': net_partition['id'],
            'name': net_partition['name'],
            'l3dom_tmplt_id': net_partition['l3dom_tmplt_id'],
            'l2dom_tmplt_id': net_partition['l2dom_tmplt_id']}


def make_net_partition_list(net_partitions):
    return [make_net_partition_dict(net_partition) for net_partition in
            net_partitions]


def make_route_dict(route):
    return {'destination': route['destination'],
            'nexthop': route['nexthop'],
            'router_id': route['router_id']}


def make_route_list(routes):
    return [make_route_dict(route) for route in routes]


def make_subnl2dom_dict(subl2dom):
    return {'subnet_id': subl2dom['subnet_id'],
            'net_partition_id': subl2dom['net_partition_id'],
            'nuage_subnet_id': subl2dom['nuage_subnet_id'],
            'nuage_l2dom_tmplt_id': subl2dom['nuage_l2dom_tmplt_id'],
            'nuage_user_id': subl2dom['nuage_user_id'],
            'nuage_group_id': subl2dom['nuage_group_id']}


def make_entrtr_dict(entrtr):
    return {'net_partition_id': entrtr['net_partition_id'],
            'router_id': entrtr['router_id'],
            'nuage_router_id': entrtr['nuage_router_id']}

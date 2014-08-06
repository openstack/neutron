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

from oslo.config import cfg
import sqlalchemy.orm.exc as db_exc

from neutron import context as ncontext
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import securitygroups_db
from neutron.openstack.common import importutils
from neutron.openstack.common import log
from neutron.openstack.common.gettextutils import _LE, _LI, _LW
from neutron.plugins.nuage.common import config
from neutron.plugins.nuage import nuagedb


LOG = log.getLogger(__name__)
NUAGE_CONFIG_FILE = '/etc/neutron/plugins/nuage/nuage_plugin.ini'


class SyncManager(db_base_plugin_v2.NeutronDbPluginV2,
                  extraroute_db.ExtraRoute_db_mixin,
                  securitygroups_db.SecurityGroupDbMixin):
    """
    This class provides functionality to sync data between OpenStack and VSD.
    """

    def __init__(self, nuageclient):
        self.context = ncontext.get_admin_context()
        self.nuageclient = nuageclient

    def synchronize(self, fipquota):
        LOG.info(_LI("Starting the sync between Neutron and VSD"))
        try:
            # Get all data to determine the resources to sync
            data = self._get_all_data()
            resources = self.nuageclient.get_resources_to_sync(data)

            # Sync all resources
            self._sync(resources, fipquota)
        except Exception as e:
            LOG.error(_LE("Cannot complete the sync between Neutron and VSD "
                          "because of error:%s"), str(e))
            return

        LOG.info(_LI("Sync between Neutron and VSD completed successfully"))

    def _get_all_data(self):
        # Get all net-partitions
        net_partition_list = nuagedb.get_all_net_partitions(
            self.context.session)

        # Get all subnet ids
        subnet_id_list = nuagedb.get_subnet_ids(self.context.session)

        # Get all router ids
        router_id_list = nuagedb.get_router_ids(self.context.session)

        # Get all ports
        port_list = self.get_ports(self.context)

        # Get all routes
        route_list = nuagedb.get_all_routes(self.context.session)

        # Get all floatingips
        fip_list = self.get_floatingips(self.context)

        # Get all securitygrp ids
        secgrp_id_list = nuagedb.get_secgrp_ids(self.context.session)

        # Get all securitygrprules
        secgrprule_id_list = self.get_security_group_rules(self.context)

        # Get all portbindings
        portbinding_list = self._get_port_security_group_bindings(self.context)

        data = {
            'netpartition': net_partition_list,
            'subnet': subnet_id_list,
            'router': router_id_list,
            'port': port_list,
            'route': route_list,
            'fip': fip_list,
            'secgroup': secgrp_id_list,
            'secgrouprule': secgrprule_id_list,
            'portbinding': portbinding_list,
        }
        return data

    def _sync(self, resources, fip_quota):
        # Sync net-partitions
        net_partition_id_dict = self.sync_net_partitions(fip_quota, resources)

        # Sync sharednetworks
        self.sync_sharednetworks(resources)

        # Sync l2domains
        self.sync_l2domains(net_partition_id_dict, resources)

        # Sync domains
        self.sync_domains(net_partition_id_dict, resources)

        # Sync domainsubnets
        self.sync_domainsubnets(resources)

        # Sync routes
        self.sync_routes(resources)

        # Sync vms
        self.sync_vms(resources)

        # Sync secgrps
        self.sync_secgrps(resources)

        # Sync secgrprules
        self.sync_secgrp_rules(resources)

        # Sync fips
        self._sync_fips(resources)

        # Delete the old net-partitions
        for net_id in net_partition_id_dict:
            nuagedb.delete_net_partition_by_id(self.context.session,
                                               net_id)

    def sync_net_partitions(self, fip_quota, resources):
        net_partition_id_dict = {}
        for netpart_id in resources['netpartition']['add']:
            with self.context.session.begin(subtransactions=True):
                netpart = self._get_netpart_data(netpart_id)
                if netpart:
                    result = self.nuageclient.create_netpart(netpart,
                                                             fip_quota)
                    netpart = result.get(netpart_id)
                    if netpart:
                        net_partition_id_dict[netpart_id] = netpart['id']
                        nuagedb.add_net_partition(
                            self.context.session,
                            netpart['id'],
                            netpart['l3dom_tmplt_id'],
                            netpart['l2dom_tmplt_id'],
                            netpart['name'])

        return net_partition_id_dict

    def sync_sharednetworks(self, resources):
        for sharednet_id in resources['sharednetwork']['add']:
            with self.context.session.begin(subtransactions=True):
                subnet, subl2dom = self._get_subnet_data(
                    sharednet_id,
                    get_mapping=False)
                if subnet:
                    self.nuageclient.create_sharednetwork(subnet)

    def sync_l2domains(self, net_partition_id_dict, resources):
        for l2dom_id in resources['l2domain']['add']:
            with self.context.session.begin(subtransactions=True):
                subnet, subl2dom = self._get_subnet_data(l2dom_id)
                if subnet:
                    # if subnet exists, subl2dom will exist
                    netpart_id = subl2dom['net_partition_id']
                    if netpart_id in net_partition_id_dict.keys():
                        # Use the id of the newly created net_partition
                        netpart_id = net_partition_id_dict[netpart_id]

                    result = self.nuageclient.create_l2domain(netpart_id,
                                                              subnet)
                    if result:
                        nuagedb.get_update_subnetl2dom_mapping(
                            self.context.session,
                            result)

    def sync_domains(self, net_partition_id_dict, resources):
        for domain_id in resources['domain']['add']:
            with self.context.session.begin(subtransactions=True):
                router, entrtr = self._get_router_data(domain_id)
                if router:
                    # if router exists, entrtr will exist
                    netpart_id = entrtr['net_partition_id']
                    if netpart_id in net_partition_id_dict.keys():
                        # Use the id of the newly created net_partition
                        netpart_id = net_partition_id_dict[netpart_id]

                    netpart = nuagedb.get_net_partition_by_id(
                        self.context.session,
                        netpart_id)
                    result = self.nuageclient.create_domain(netpart, router)
                    if result:
                        nuagedb.get_update_entrtr_mapping(self.context.session,
                                                          result)

    def sync_domainsubnets(self, resources):
        for domsubn_id in resources['domainsubnet']['add']:
            # This is a dict of subn_id and the router interface port
            subn_rtr_intf_port_dict = (
                resources['port']['sub_rtr_intf_port_dict'])
            port_id = subn_rtr_intf_port_dict[domsubn_id]
            port = self._get_port_data(port_id)
            if port:
                with self.context.session.begin(subtransactions=True):
                    subnet, subl2dom = self._get_subnet_data(domsubn_id)
                    if subnet:
                        result = self.nuageclient.create_domainsubnet(subnet,
                                                                      port)
                        if result:
                            nuagedb.get_update_subnetl2dom_mapping(
                                self.context.session,
                                result)

    def sync_routes(self, resources):
        for rt in resources['route']['add']:
            with self.context.session.begin(subtransactions=True):
                route = self._get_route_data(rt)
                if route:
                    self.nuageclient.create_route(route)

    def sync_vms(self, resources):
        for port_id in resources['port']['vm']:
            port = self._get_port_data(port_id)
            if port:
                self.nuageclient.create_vm(port)

    def sync_secgrps(self, resources):
        secgrp_dict = resources['security']['secgroup']
        for secgrp_id, ports in secgrp_dict['l2domain']['add'].iteritems():
            with self.context.session.begin(subtransactions=True):
                secgrp = self._get_sec_grp_data(secgrp_id)
                if secgrp:
                    self.nuageclient.create_security_group(secgrp, ports)

        for secgrp_id, ports in secgrp_dict['domain']['add'].iteritems():
            with self.context.session.begin(subtransactions=True):
                secgrp = self._get_sec_grp_data(secgrp_id)
                if secgrp:
                    self.nuageclient.create_security_group(secgrp, ports)

    def sync_secgrp_rules(self, resources):
        secrule_list = resources['security']['secgrouprule']
        for secrule_id in secrule_list['l2domain']['add']:
            with self.context.session.begin(subtransactions=True):
                secgrprule = self._get_sec_grp_rule_data(secrule_id)
                if secgrprule:
                    self.nuageclient.create_security_group_rule(secgrprule)

        for secrule_id in secrule_list['domain']['add']:
            with self.context.session.begin(subtransactions=True):
                secgrprule = self._get_sec_grp_rule_data(secrule_id)
                if secgrprule:
                    self.nuageclient.create_security_group_rule(secgrprule)

    def _sync_fips(self, resources):
        for fip_id in resources['fip']['add']:
            with self.context.session.begin(subtransactions=True):
                fip = self._get_fip_data(fip_id)
                if fip:
                    ipalloc = self._get_ipalloc_for_fip(fip)
                    self.nuageclient.create_fip(fip, ipalloc)

        for fip_id in resources['fip']['disassociate']:
            with self.context.session.begin(subtransactions=True):
                fip = self._get_fip_data(fip_id)
                if fip:
                    self.nuageclient.disassociate_fip(fip)

        for fip_id in resources['fip']['associate']:
            with self.context.session.begin(subtransactions=True):
                fip = self._get_fip_data(fip_id)
                if fip:
                    self.nuageclient.associate_fip(fip)

    def _get_subnet_data(self, subnet_id, get_mapping=True):
        subnet = None
        subl2dom = None
        try:
            if get_mapping:
                subl2dom_db = nuagedb.get_subnet_l2dom_with_lock(
                    self.context.session,
                    subnet_id)
                subl2dom = nuagedb.make_subnl2dom_dict(subl2dom_db)

            subnet_db = nuagedb.get_subnet_with_lock(self.context.session,
                                                     subnet_id)
            subnet = self._make_subnet_dict(subnet_db)
        except db_exc.NoResultFound:
            LOG.warning(_LW("Subnet %s not found in neutron for sync"),
                        subnet_id)

        return subnet, subl2dom

    def _get_router_data(self, router_id):
        router = None
        entrtr = None
        try:
            entrtr_db = nuagedb.get_ent_rtr_mapping_with_lock(
                self.context.session,
                router_id)
            entrtr = nuagedb.make_entrtr_dict(entrtr_db)

            router_db = nuagedb.get_router_with_lock(self.context.session,
                                                     router_id)
            router = self._make_router_dict(router_db)
        except db_exc.NoResultFound:
            LOG.warning(_LW("Router %s not found in neutron for sync"),
                        router_id)

        return router, entrtr

    def _get_route_data(self, rt):
        route = None
        try:
            route = nuagedb.get_route_with_lock(self.context.session,
                                                rt['destination'],
                                                rt['nexthop'])
        except db_exc.NoResultFound:
            LOG.warning(_LW("Route with destination %(dest)s and nexthop "
                            "%(hop)s not found in neutron for sync"),
                        {'dest': rt['destination'],
                         'hop': rt['nexthop']})

        return route

    def _get_sec_grp_data(self, secgrp_id):
        secgrp = None
        try:
            secgrp_db = nuagedb.get_secgrp_with_lock(self.context.session,
                                                     secgrp_id)
            secgrp = self._make_security_group_dict(secgrp_db)
        except db_exc.NoResultFound:
            LOG.warning(_LW("Security group %s not found in neutron for sync"),
                        secgrp_id)
        return secgrp

    def _get_sec_grp_rule_data(self, secgrprule_id):
        secgrprule = None
        try:
            secrule_db = nuagedb.get_secgrprule_with_lock(self.context.session,
                                                          secgrprule_id)
            secgrprule = self._make_security_group_rule_dict(secrule_db)
        except db_exc.NoResultFound:
            LOG.warning(_LW("Security group rule %s not found in neutron for "
                            "sync"), secgrprule_id)
        return secgrprule

    def _get_fip_data(self, fip_id):
        fip = None
        try:
            fip_db = nuagedb.get_fip_with_lock(self.context.session, fip_id)
            fip = self._make_floatingip_dict(fip_db)
        except db_exc.NoResultFound:
            LOG.warning(_LW("Floating ip %s not found in neutron for sync"),
                        fip_id)
        return fip

    def _get_ipalloc_for_fip(self, fip):
        ipalloc = None
        try:
            ipalloc = nuagedb.get_ipalloc_for_fip(self.context.session,
                                                  fip['floating_network_id'],
                                                  fip['floating_ip_address'],
                                                  lock=True)
        except db_exc.NoResultFound:
            LOG.warning(_LW("IP allocation for floating ip %s not found in "
                            "neutron for sync"), fip['id'])
        return ipalloc

    def _get_netpart_data(self, netpart_id):
        netpart = None
        try:
            netpart = nuagedb.get_net_partition_with_lock(
                self.context.session,
                netpart_id)
        except db_exc.NoResultFound:
            LOG.warning(_LW("Net-partition %s not found in neutron for sync"),
                        netpart_id)
        return netpart

    def _get_port_data(self, port_id):
        port = None
        try:
            port_db = nuagedb.get_port_with_lock(self.context.session, port_id)
            port = self._make_port_dict(port_db)
        except db_exc.NoResultFound:
            LOG.warning(_LW("VM port %s not found in neutron for sync"),
                        port_id)
        return port


def main():
    cfg.CONF(default_config_files=(
        [NUAGE_CONFIG_FILE]))
    config.nuage_register_cfg_opts()
    server = cfg.CONF.RESTPROXY.server
    serverauth = cfg.CONF.RESTPROXY.serverauth
    serverssl = cfg.CONF.RESTPROXY.serverssl
    base_uri = cfg.CONF.RESTPROXY.base_uri
    auth_resource = cfg.CONF.RESTPROXY.auth_resource
    organization = cfg.CONF.RESTPROXY.organization
    fipquota = str(cfg.CONF.RESTPROXY.default_floatingip_quota)
    logging = importutils.import_module('logging')
    nuageclientinst = importutils.import_module('nuagenetlib.nuageclient')
    nuageclient = nuageclientinst.NuageClient(server, base_uri,
                                              serverssl, serverauth,
                                              auth_resource,
                                              organization)
    logging.basicConfig(level=logging.DEBUG)
    SyncManager(nuageclient).synchronize(fipquota)

if __name__ == '__main__':
    main()

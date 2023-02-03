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

import abc
from datetime import datetime
import itertools

from eventlet import greenthread
from neutron_lib.api.definitions import l3
from neutron_lib.api.definitions import segment as segment_def
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.utils import helpers
from oslo_log import log

from neutron.common.ovn import acl as acl_utils
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron import manager
from neutron.objects.port_forwarding import PortForwarding
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.extensions import qos \
    as ovn_qos
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_client
from neutron.services.segments import db as segments_db


LOG = log.getLogger(__name__)

SYNC_MODE_OFF = 'off'
SYNC_MODE_LOG = 'log'
SYNC_MODE_REPAIR = 'repair'


class OvnDbSynchronizer(object, metaclass=abc.ABCMeta):

    def __init__(self, core_plugin, ovn_api, ovn_driver):
        self.ovn_driver = ovn_driver
        self.ovn_api = ovn_api
        self.core_plugin = core_plugin

    def sync(self, delay_seconds=10):
        self._gt = greenthread.spawn_after_local(delay_seconds, self.do_sync)

    @abc.abstractmethod
    def do_sync(self):
        """Method to sync the OVN DB."""

    def stop(self):
        try:
            self._gt.kill()
        except AttributeError:
            # Haven't started syncing
            pass


class OvnNbSynchronizer(OvnDbSynchronizer):
    """Synchronizer class for NB."""

    def __init__(self, core_plugin, ovn_api, sb_ovn, mode, ovn_driver):
        super(OvnNbSynchronizer, self).__init__(
            core_plugin, ovn_api, ovn_driver)
        self.mode = mode
        self.l3_plugin = directory.get_plugin(plugin_constants.L3)
        self.pf_plugin = directory.get_plugin(plugin_constants.PORTFORWARDING)
        if not self.pf_plugin:
            self.pf_plugin = (
                manager.NeutronManager.load_class_for_provider(
                    'neutron.service_plugins', 'port_forwarding')())
        self._ovn_client = ovn_client.OVNClient(ovn_api, sb_ovn)
        self.segments_plugin = directory.get_plugin('segments')
        if not self.segments_plugin:
            self.segments_plugin = (
                manager.NeutronManager.load_class_for_provider(
                    'neutron.service_plugins', 'segments')())

    def stop(self):
        if utils.is_ovn_l3(self.l3_plugin):
            self.l3_plugin._nb_ovn.ovsdb_connection.stop()
            self.l3_plugin._sb_ovn.ovsdb_connection.stop()
        super(OvnNbSynchronizer, self).stop()

    def do_sync(self):
        if self.mode == SYNC_MODE_OFF:
            LOG.debug("Neutron sync mode is off")
            return
        LOG.debug("Starting OVN-Northbound DB sync process")

        ctx = context.get_admin_context()

        self.sync_port_groups(ctx)
        self.sync_networks_ports_and_dhcp_opts(ctx)
        self.sync_port_dns_records(ctx)
        self.sync_acls(ctx)
        self.sync_routers_and_rports(ctx)
        self.migrate_to_stateful_fips(ctx)
        self.sync_port_qos_policies(ctx)
        self.sync_fip_qos_policies(ctx)

    def _create_port_in_ovn(self, ctx, port):
        # Remove any old ACLs for the port to avoid creating duplicate ACLs.
        self.ovn_api.delete_acl(
            utils.ovn_name(port['network_id']),
            port['id']).execute(check_error=True)

        # Create the port in OVN. This will include ACL and Address Set
        # updates as needed.
        self._ovn_client.create_port(ctx, port)

    def remove_common_acls(self, neutron_acls, nb_acls):
        """Take out common acls of the two acl dictionaries.

        @param   neutron_acls: neutron dictionary of port vs acls
        @type    neutron_acls: {}
        @param   nb_acls: nb dictionary of port vs acls
        @type    nb_acls: {}
        @return: Nothing, original dictionary modified
        """
        for port in neutron_acls.keys():
            for acl in list(neutron_acls[port]):
                if port in nb_acls and acl in nb_acls[port]:
                    neutron_acls[port].remove(acl)
                    nb_acls[port].remove(acl)

    def get_acls(self, context):
        """create the list of ACLS in OVN.

        @param context: neutron_lib.context
        @type  context: object of type neutron_lib.context.Context
        @var   lswitch_names: List of lswitch names
        @var   acl_list: List of NB acls
        @var   acl_list_dict: Dictionary of acl-lists based on lport as key
        @return: acl_list-dict
        """
        lswitch_names = set([])
        for network in self.core_plugin.get_networks(context):
            lswitch_names.add(network['id'])
        acl_dict, ignore1, ignore2 = (
            self.ovn_api.get_acls_for_lswitches(lswitch_names))
        acl_list = list(itertools.chain(*acl_dict.values()))
        acl_list_dict = {}
        for acl in acl_list:
            acl = acl_utils.filter_acl_dict(
                acl, extra_fields=['lport', 'lswitch'])
            key = acl['lport']
            if key in acl_list_dict:
                acl_list_dict[key].append(acl)
            else:
                acl_list_dict[key] = list([acl])
        return acl_list_dict

    def sync_port_groups(self, ctx):
        """Sync Port Groups between neutron and NB.

        @param ctx: neutron_lib.context
        @type  ctx: object of type neutron_lib.context.Context
        """

        neutron_sgs = {}
        neutron_pgs = set()
        with db_api.CONTEXT_READER.using(ctx):
            for sg in self.core_plugin.get_security_groups(ctx):
                pg_name = utils.ovn_port_group_name(sg['id'])
                neutron_pgs.add(pg_name)
                neutron_sgs[pg_name] = sg['id']
            neutron_pgs.add(ovn_const.OVN_DROP_PORT_GROUP_NAME)

        ovn_pgs = set()
        port_groups = self.ovn_api.db_list_rows('Port_Group').execute() or []
        for pg in port_groups:
            ovn_pgs.add(pg.name)

        add_pgs = neutron_pgs.difference(ovn_pgs)
        remove_pgs = ovn_pgs.difference(neutron_pgs)

        LOG.debug('Port Groups added %d, removed %d',
                  len(add_pgs), len(remove_pgs))

        if self.mode == SYNC_MODE_REPAIR:
            LOG.debug('Port-Group-SYNC: transaction started @ %s',
                      str(datetime.now()))
            if add_pgs:
                db_ports = self.core_plugin.get_ports(ctx)
                ovn_ports = set(p.name for p in
                                self.ovn_api.lsp_list().execute())
            with self.ovn_api.transaction(check_error=True) as txn:
                pg = ovn_const.OVN_DROP_PORT_GROUP_NAME
                # Process default drop port group first
                if pg in add_pgs:
                    txn.add(self.ovn_api.pg_add(name=pg, acls=[]))
                    add_pgs.remove(pg)
                    # Add ports to the drop port group. Only add those that
                    # already exists in OVN. The rest will be added during the
                    # ports sync operation later.
                    for n_port in db_ports:
                        if ((utils.is_security_groups_enabled(n_port) or
                             utils.is_port_security_enabled(n_port)) and
                                n_port['id'] in ovn_ports):
                            txn.add(self.ovn_api.pg_add_ports(
                                pg, n_port['id']))

                for pg in add_pgs:
                    # If it's a security group PG, add the ext id
                    ext_ids = {ovn_const.OVN_SG_EXT_ID_KEY: neutron_sgs[pg]}
                    txn.add(self.ovn_api.pg_add(name=pg, acls=[],
                                                external_ids=ext_ids))
                    # Add the ports belonging to the SG to this port group
                    for n_port in db_ports:
                        if (neutron_sgs[pg] in n_port['security_groups'] and
                                n_port['id'] in ovn_ports):
                            txn.add(self.ovn_api.pg_add_ports(
                                pg, n_port['id']))
                for pg in remove_pgs:
                    txn.add(self.ovn_api.pg_del(pg))
            LOG.debug('Port-Group-SYNC: transaction finished @ %s',
                      str(datetime.now()))

    def _get_acls_from_port_groups(self):
        ovn_acls = []
        acl_columns = (self.ovn_api._tables['ACL'].columns.keys() &
                       set(ovn_const.ACL_EXPECTED_COLUMNS_NBDB))
        acl_columns.discard('external_ids')
        for pg in self.ovn_api.db_list_rows('Port_Group').execute():
            acls = getattr(pg, 'acls', [])
            for acl in acls:
                acl_string = {k: getattr(acl, k) for k in acl_columns}
                acl_string['port_group'] = pg.name
                ovn_acls.append(acl_string)
        return ovn_acls

    def sync_acls(self, ctx):
        """Sync ACLs between neutron and NB.

        @param ctx: neutron_lib.context
        @type  ctx: object of type neutron_lib.context.Context
        @return: Nothing
        """
        LOG.debug('ACL-SYNC: started @ %s', str(datetime.now()))

        neutron_acls = []
        # if allow-stateless supported, we have to fetch groups to determine if
        # stateful is set
        if self._ovn_client.is_allow_stateless_supported():
            for sg in self.core_plugin.get_security_groups(ctx):
                stateful = sg.get("stateful", True)
                pg_name = utils.ovn_port_group_name(sg['id'])
                for sgr in self.core_plugin.get_security_group_rules(
                        ctx, {'security_group_id': sg['id']}):
                    neutron_acls.append(
                        acl_utils._add_sg_rule_acl_for_port_group(
                            pg_name, stateful, sgr)
                    )
        else:
            # TODO(ihrachys) remove when min OVN version >= 21.06
            for sgr in self.core_plugin.get_security_group_rules(ctx):
                pg_name = utils.ovn_port_group_name(sgr['security_group_id'])
                neutron_acls.append(acl_utils._add_sg_rule_acl_for_port_group(
                    pg_name, True, sgr))
        neutron_acls += acl_utils.add_acls_for_drop_port_group(
            ovn_const.OVN_DROP_PORT_GROUP_NAME)

        ovn_acls = self._get_acls_from_port_groups()

        # We need to remove also all the ACLs applied to Logical Switches
        def get_num_acls(ovn_acls):
            return len([item for sublist in ovn_acls for item in sublist[1]])

        ovn_acls_from_ls = [(row.name, row.acls) for row in (
            self.ovn_api._tables['Logical_Switch'].rows.values())]
        num_acls_to_remove_from_ls = get_num_acls(ovn_acls_from_ls)

        # Remove the common ones
        for na in list(neutron_acls):
            for ovn_a in ovn_acls:
                if all(item in na.items() for item in ovn_a.items()):
                    neutron_acls.remove(na)
                    ovn_acls.remove(ovn_a)
                    break

        num_acls_to_add = len(neutron_acls)
        num_acls_to_remove = len(ovn_acls) + num_acls_to_remove_from_ls
        if num_acls_to_add != 0 or num_acls_to_remove != 0:
            LOG.warning('ACLs-to-be-added %(add)d '
                        'ACLs-to-be-removed %(remove)d',
                        {'add': num_acls_to_add,
                         'remove': num_acls_to_remove})

        if self.mode == SYNC_MODE_REPAIR:
            with self.ovn_api.transaction(check_error=True) as txn:
                for acla in neutron_acls:
                    LOG.warning('ACL found in Neutron but not in '
                                'OVN DB for port group %s', acla['port_group'])
                    txn.add(self.ovn_api.pg_acl_add(**acla, may_exist=True))

            with self.ovn_api.transaction(check_error=True) as txn:
                for aclr in ovn_acls:
                    LOG.warning('ACLs found in OVN DB but not in '
                                'Neutron for port group %s',
                                aclr['port_group'])
                    txn.add(self.ovn_api.pg_acl_del(aclr['port_group'],
                                                    aclr['direction'],
                                                    aclr['priority'],
                                                    aclr['match']))
                for aclr in ovn_acls_from_ls:
                    # Remove all the ACLs from any Logical Switch if they have
                    # any. Elements are (lswitch_name, list_of_acls).
                    if len(aclr[1]) > 0:
                        LOG.warning('Removing ACLs from OVN from Logical '
                                    'Switch %s', aclr[0])
                        txn.add(self.ovn_api.acl_del(aclr[0]))

        LOG.debug('ACL-SYNC: finished @ %s', str(datetime.now()))

    def _calculate_routes_differences(self, ovn_routes, db_routes):
        to_add = []
        to_remove = []
        for db_route in db_routes:
            for ovn_route in ovn_routes:
                if (ovn_route['destination'] == db_route['destination'] and
                        ovn_route['nexthop'] == db_route['nexthop']):
                    break
            else:
                to_add.append(db_route)

        for ovn_route in ovn_routes:
            for db_route in db_routes:
                if (ovn_route['destination'] == db_route['destination'] and
                        ovn_route['nexthop'] == db_route['nexthop']):
                    break
            else:
                to_remove.append(ovn_route)

        return to_add, to_remove

    def _calculate_fips_differences(self, ovn_fips, ovn_rtr_lb_pfs, db_fips):
        to_add = []
        to_remove = []
        ovn_pfs = utils.parse_ovn_lb_port_forwarding(ovn_rtr_lb_pfs)
        for db_fip in db_fips:
            # skip fips that are used for port forwarding
            if db_fip['id'] in ovn_pfs:
                continue
            for ovn_fip in ovn_fips:
                if (ovn_fip['logical_ip'] == db_fip['fixed_ip_address'] and
                        ovn_fip['external_ip'] ==
                        db_fip['floating_ip_address']):
                    break
            else:
                to_add.append(db_fip)

        for ovn_fip in ovn_fips:
            for db_fip in db_fips:
                if (ovn_fip['logical_ip'] == db_fip['fixed_ip_address'] and
                        ovn_fip['external_ip'] ==
                        db_fip['floating_ip_address']):
                    break
            else:
                to_remove.append(ovn_fip)

        return to_add, to_remove

    def _unroll_port_forwarding(self, db_pf):
        pf = PortForwarding(**db_pf)
        pfs = pf.unroll_port_ranges()
        return [p.to_dict() for p in pfs]

    def _calculate_fip_pfs_differences(self, ovn_rtr_lb_pfs, db_pfs):
        to_add_or_update = set()
        to_remove = []
        ovn_pfs = utils.parse_ovn_lb_port_forwarding(ovn_rtr_lb_pfs)

        # check that all pfs are accounted for in ovn_pfs by building
        # a set for each protocol and then comparing it with ovn_pfs
        db_mapped_pfs = {}
        for db_pf in db_pfs:
            for pf in self._unroll_port_forwarding(db_pf):
                fip_id = pf.get('floatingip_id')
                protocol = self.l3_plugin.port_forwarding.ovn_lb_protocol(
                    pf.get('protocol'))
                db_vip = "{}:{} {}:{}".format(
                    pf.get('floating_ip_address'), pf.get('external_port'),
                    pf.get('internal_ip_address'), pf.get('internal_port'))

                fip_dict = db_mapped_pfs.get(fip_id, {})
                fip_dict_proto = fip_dict.get(protocol, set())
                fip_dict_proto.add(db_vip)
                if protocol not in fip_dict:
                    fip_dict[protocol] = fip_dict_proto
                if fip_id not in db_mapped_pfs:
                    db_mapped_pfs[fip_id] = fip_dict
        for fip_id in db_mapped_pfs:
            ovn_pfs_fip_id = ovn_pfs.get(fip_id, {})
            # check for cases when ovn has lbs for protocols that are not in
            # neutron db
            if len(db_mapped_pfs[fip_id]) != len(ovn_pfs_fip_id):
                to_add_or_update.add(fip_id)
                continue
            # check that vips in each protocol are an exact match
            for protocol in db_mapped_pfs[fip_id]:
                ovn_fip_dict_proto = ovn_pfs_fip_id.get(protocol)
                if db_mapped_pfs[fip_id][protocol] != ovn_fip_dict_proto:
                    to_add_or_update.add(fip_id)

        # remove pf entries that exist in ovn lb but have no fip in
        # neutron db.
        for fip_id in ovn_pfs:
            for db_pf in db_pfs:
                pf_fip_id = db_pf.get('floatingip_id')
                if pf_fip_id == fip_id:
                    break
            else:
                to_remove.append(fip_id)

        return list(to_add_or_update), to_remove

    def _create_or_update_floatingip_pfs(self, context, fip_id, txn):
        self.l3_plugin.port_forwarding.db_sync_create_or_update(
            context, fip_id, txn)

    def _delete_floatingip_pfs(self, context, fip_id, txn):
        self.l3_plugin.port_forwarding.db_sync_delete(
            context, fip_id, txn)

    def sync_routers_and_rports(self, ctx):
        """Sync Routers between neutron and NB.

        @param ctx: neutron_lib.context
        @type  ctx: object of type neutron_lib.context.Context
        @var   db_routers: List of Routers from neutron DB
        @var   db_router_ports: List of Router ports from neutron DB
        @var   lrouters: NB dictionary of logical routers and
               the corresponding logical router ports.
               vs list-of-acls
        @var   del_lrouters_list: List of Routers that need to be
               deleted from NB
        @var   del_lrouter_ports_list: List of Router ports that need to be
               deleted from NB
        @return: Nothing
        """
        if not utils.is_ovn_l3(self.l3_plugin):
            LOG.debug("OVN L3 mode is disabled, skipping "
                      "sync routers and router ports")
            return

        LOG.debug('OVN-NB Sync Routers and Router ports started @ %s',
                  str(datetime.now()))

        db_routers = {}
        db_extends = {}
        db_router_ports = {}
        for router in self.l3_plugin.get_routers(ctx):
            db_routers[router['id']] = router
            db_extends[router['id']] = {}
            db_extends[router['id']]['routes'] = []
            db_extends[router['id']]['snats'] = []
            db_extends[router['id']]['fips'] = []
            db_extends[router['id']]['fips_pfs'] = []
            if not router.get(l3.EXTERNAL_GW_INFO):
                continue
            gateways = self._ovn_client._get_gw_info(ctx, router)
            for gw_info in gateways:
                prefix = (constants.IPv4_ANY if
                          gw_info.ip_version == constants.IP_VERSION_4 else
                          constants.IPv6_ANY)
                if gw_info.gateway_ip:
                    db_extends[router['id']]['routes'].append(
                        {'destination': prefix,
                         'nexthop': gw_info.gateway_ip,
                         'external_ids': {
                             ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                             ovn_const.OVN_SUBNET_EXT_ID_KEY:
                             gw_info.subnet_id}})
                if gw_info.ip_version == constants.IP_VERSION_6:
                    continue
                if gw_info.router_ip and utils.is_snat_enabled(router):
                    networks = (
                        self._ovn_client._get_v4_network_of_all_router_ports(
                            ctx, router['id']))
                    for network in networks:
                        db_extends[router['id']]['snats'].append({
                            'logical_ip': network,
                            'external_ip': gw_info.router_ip,
                            'type': 'snat'})

        fips = self.l3_plugin.get_floatingips(
            ctx, {'router_id': list(db_routers.keys())})
        for fip in fips:
            db_extends[fip['router_id']]['fips'].append(fip)
            if self.pf_plugin:
                fip_pfs = self.pf_plugin.get_floatingip_port_forwardings(
                    ctx, fip['id'])
                for fip_pf in fip_pfs:
                    db_extends[fip['router_id']]['fips_pfs'].append(fip_pf)
        interfaces = self.l3_plugin._get_sync_interfaces(
            ctx, list(db_routers.keys()),
            [constants.DEVICE_OWNER_ROUTER_INTF,
             constants.DEVICE_OWNER_ROUTER_GW,
             constants.DEVICE_OWNER_DVR_INTERFACE,
             constants.DEVICE_OWNER_ROUTER_HA_INTF,
             constants.DEVICE_OWNER_HA_REPLICATED_INT])
        for interface in interfaces:
            db_router_ports[interface['id']] = interface

        lrouters = self.ovn_api.get_all_logical_routers_with_rports()

        del_lrouters_list = []
        del_lrouter_ports_list = []
        update_sroutes_list = []
        update_lrport_list = []
        update_snats_list = []
        update_fips_list = []
        update_pfs_list = []
        for lrouter in lrouters:
            ovn_rtr_lb_pfs = self.ovn_api.get_router_floatingip_lbs(
                utils.ovn_name(lrouter['name']))
            if lrouter['name'] in db_routers:
                for lrport, lrport_nets in lrouter['ports'].items():
                    if lrport in db_router_ports:
                        # We dont have to check for the networks and
                        # ipv6_ra_configs values. Lets add it to the
                        # update_lrport_list. If they are in sync, then
                        # update_router_port will be a no-op.
                        update_lrport_list.append(db_router_ports[lrport])
                        del db_router_ports[lrport]
                    else:
                        del_lrouter_ports_list.append(
                            {'port': lrport, 'lrouter': lrouter['name']})
                if 'routes' in db_routers[lrouter['name']]:
                    db_routes = db_routers[lrouter['name']]['routes']
                else:
                    db_routes = []
                if 'routes' in db_extends[lrouter['name']]:
                    db_routes.extend(db_extends[lrouter['name']]['routes'])

                ovn_routes = lrouter['static_routes']
                add_routes, del_routes = self._calculate_routes_differences(
                    ovn_routes, db_routes)
                update_sroutes_list.append({'id': lrouter['name'],
                                            'add': add_routes,
                                            'del': del_routes})
                ovn_fips = lrouter['dnat_and_snats']
                db_fips = db_extends[lrouter['name']]['fips']
                add_fips, del_fips = self._calculate_fips_differences(
                    ovn_fips, ovn_rtr_lb_pfs, db_fips)
                update_fips_list.append({'id': lrouter['name'],
                                         'add': add_fips,
                                         'del': del_fips})
                db_fips_pfs = db_extends[lrouter['name']]['fips_pfs']
                add_fip_pfs, del_fip_pfs = self._calculate_fip_pfs_differences(
                    ovn_rtr_lb_pfs, db_fips_pfs)
                update_pfs_list.append({'id': lrouter['name'],
                                        'add': add_fip_pfs,
                                        'del': del_fip_pfs})
                ovn_nats = lrouter['snats']
                db_snats = db_extends[lrouter['name']]['snats']
                add_snats, del_snats = helpers.diff_list_of_dict(
                    ovn_nats, db_snats)
                update_snats_list.append({'id': lrouter['name'],
                                          'add': add_snats,
                                          'del': del_snats})
            else:
                del_lrouters_list.append(lrouter)

        lrouters_names = {lr['name'] for lr in lrouters}
        for r_id, router in db_routers.items():
            if r_id in lrouters_names:
                continue
            LOG.warning("Router found in Neutron but not in "
                        "OVN DB, router id=%s", router['id'])
            if self.mode == SYNC_MODE_REPAIR:
                try:
                    LOG.warning("Creating the router %s in OVN NB DB",
                                router['id'])
                    self._ovn_client.create_router(
                        ctx, router, add_external_gateway=False)
                    if 'routes' in router:
                        update_sroutes_list.append(
                            {'id': router['id'], 'add': router['routes'],
                             'del': []})
                    if 'routes' in db_extends[router['id']]:
                        update_sroutes_list.append(
                            {'id': router['id'],
                             'add': db_extends[router['id']]['routes'],
                             'del': []})
                    if 'snats' in db_extends[router['id']]:
                        update_snats_list.append(
                            {'id': router['id'],
                             'add': db_extends[router['id']]['snats'],
                             'del': []})
                    if 'fips' in db_extends[router['id']]:
                        update_fips_list.append(
                            {'id': router['id'],
                             'add': db_extends[router['id']]['fips'],
                             'del': []})
                    if 'fips_pfs' in db_extends[router['id']]:
                        add_fip_pfs = {
                            db_pf['floatingip_id'] for
                            db_pf in db_extends[router['id']]['fips_pfs']}
                        update_pfs_list.append(
                            {'id': router['id'],
                             'add': list(add_fip_pfs),
                             'del': []})
                except RuntimeError:
                    LOG.warning("Create router in OVN NB failed for router %s",
                                router['id'])

        for rp_id, rrport in db_router_ports.items():
            LOG.warning("Router Port found in Neutron but not in OVN "
                        "DB, router port_id=%s", rrport['id'])
            if self.mode == SYNC_MODE_REPAIR:
                try:
                    LOG.warning("Creating the router port %s in OVN NB DB",
                                rrport['id'])
                    router = db_routers[rrport['device_id']]
                    self._ovn_client._create_lrouter_port(
                        ctx, router, rrport)
                except RuntimeError:
                    LOG.warning("Create router port in OVN "
                                "NB failed for router port %s", rrport['id'])

        for rport in update_lrport_list:
            LOG.warning("Router Port port_id=%s needs to be updated "
                        "for networks changed",
                        rport['id'])
            if self.mode == SYNC_MODE_REPAIR:
                try:
                    LOG.warning(
                        "Updating networks on router port %s in OVN NB DB",
                        rport['id'])
                    self._ovn_client.update_router_port(ctx, rport)
                except RuntimeError:
                    LOG.warning("Update router port networks in OVN "
                                "NB failed for router port %s", rport['id'])

        with self.ovn_api.transaction(check_error=True) as txn:
            for lrouter in del_lrouters_list:
                LOG.warning("Router found in OVN but not in "
                            "Neutron, router id=%s", lrouter['name'])
                if self.mode == SYNC_MODE_REPAIR:
                    LOG.warning("Deleting the router %s from OVN NB DB",
                                lrouter['name'])
                    txn.add(self.ovn_api.delete_lrouter(
                        utils.ovn_name(lrouter['name'])))

            for lrport_info in del_lrouter_ports_list:
                LOG.warning("Router Port found in OVN but not in "
                            "Neutron, port_id=%s", lrport_info['port'])
                if self.mode == SYNC_MODE_REPAIR:
                    LOG.warning("Deleting the port %s from OVN NB DB",
                                lrport_info['port'])
                    txn.add(self.ovn_api.delete_lrouter_port(
                        utils.ovn_lrouter_port_name(lrport_info['port']),
                        utils.ovn_name(lrport_info['lrouter']),
                        if_exists=False))
            for sroute in update_sroutes_list:
                if sroute['add']:
                    LOG.warning("Router %(id)s static routes %(route)s "
                                "found in Neutron but not in OVN",
                                {'id': sroute['id'], 'route': sroute['add']})
                    if self.mode == SYNC_MODE_REPAIR:
                        LOG.warning("Add static routes %s to OVN NB DB",
                                    sroute['add'])
                        for route in sroute['add']:
                            columns = {}
                            if 'external_ids' in route:
                                columns['external_ids'] = route['external_ids']
                            txn.add(self.ovn_api.add_static_route(
                                utils.ovn_name(sroute['id']),
                                ip_prefix=route['destination'],
                                nexthop=route['nexthop'],
                                **columns))

                if sroute['del']:
                    LOG.warning("Router %(id)s static routes %(route)s "
                                "found in OVN but not in Neutron",
                                {'id': sroute['id'], 'route': sroute['del']})
                    if self.mode == SYNC_MODE_REPAIR:
                        LOG.warning("Delete static routes %s from OVN NB DB",
                                    sroute['del'])
                        for route in sroute['del']:
                            txn.add(self.ovn_api.delete_static_route(
                                utils.ovn_name(sroute['id']),
                                ip_prefix=route['destination'],
                                nexthop=route['nexthop']))
            for fip in update_fips_list:
                if fip['del']:
                    LOG.warning("Router %(id)s floating ips %(fip)s "
                                "found in OVN but not in Neutron",
                                {'id': fip['id'], 'fip': fip['del']})
                    if self.mode == SYNC_MODE_REPAIR:
                        LOG.warning(
                            "Delete floating ips %s from OVN NB DB",
                            fip['del'])
                        for nat in fip['del']:
                            self._ovn_client._delete_floatingip(
                                nat, utils.ovn_name(fip['id']), txn=txn)
                if fip['add']:
                    LOG.warning("Router %(id)s floating ips %(fip)s "
                                "found in Neutron but not in OVN",
                                {'id': fip['id'], 'fip': fip['add']})
                    if self.mode == SYNC_MODE_REPAIR:
                        LOG.warning("Add floating ips %s to OVN NB DB",
                                    fip['add'])
                        for nat in fip['add']:
                            self._ovn_client._create_or_update_floatingip(
                                nat, txn=txn)

            for pf in update_pfs_list:
                if pf['del']:
                    LOG.warning("Router %(id)s port forwarding for floating "
                                "ips %(fip)s found in OVN but not in Neutron",
                                {'id': pf['id'], 'fip': pf['del']})
                    if self.mode == SYNC_MODE_REPAIR:
                        LOG.warning(
                            "Delete port forwarding for fips %s from "
                            "OVN NB DB",
                            pf['del'])
                        for pf_id in pf['del']:
                            self._delete_floatingip_pfs(ctx, pf_id, txn)
                if pf['add']:
                    LOG.warning("Router %(id)s port forwarding for floating "
                                "ips %(fip)s Neutron out of sync or missing "
                                "in OVN",
                                {'id': pf['id'], 'fip': pf['add']})
                    if self.mode == SYNC_MODE_REPAIR:
                        LOG.warning("Add port forwarding for fips %s "
                                    "to OVN NB DB",
                                    pf['add'])
                        for pf_fip_id in pf['add']:
                            self._create_or_update_floatingip_pfs(
                                ctx, pf_fip_id, txn)

            for snat in update_snats_list:
                if snat['del']:
                    LOG.warning("Router %(id)s snat %(snat)s "
                                "found in OVN but not in Neutron",
                                {'id': snat['id'], 'snat': snat['del']})
                    if self.mode == SYNC_MODE_REPAIR:
                        LOG.warning("Delete snats %s from OVN NB DB",
                                    snat['del'])
                        for nat in snat['del']:
                            txn.add(self.ovn_api.delete_nat_rule_in_lrouter(
                                utils.ovn_name(snat['id']),
                                logical_ip=nat['logical_ip'],
                                external_ip=nat['external_ip'],
                                type='snat'))
                if snat['add']:
                    LOG.warning("Router %(id)s snat %(snat)s "
                                "found in Neutron but not in OVN",
                                {'id': snat['id'], 'snat': snat['add']})
                    if self.mode == SYNC_MODE_REPAIR:
                        LOG.warning("Add snats %s to OVN NB DB",
                                    snat['add'])
                        for nat in snat['add']:
                            txn.add(self.ovn_api.add_nat_rule_in_lrouter(
                                utils.ovn_name(snat['id']),
                                logical_ip=nat['logical_ip'],
                                external_ip=nat['external_ip'],
                                type='snat'))
        LOG.debug('OVN-NB Sync routers and router ports finished %s',
                  str(datetime.now()))

    def _sync_subnet_dhcp_options(self, ctx, db_networks,
                                  ovn_subnet_dhcp_options):
        LOG.debug('OVN-NB Sync DHCP options for Neutron subnets started')

        db_subnets = {}
        filters = {'enable_dhcp': [True]}
        for subnet in self.core_plugin.get_subnets(ctx, filters=filters):
            if (subnet['ip_version'] == constants.IP_VERSION_6 and
                    subnet.get('ipv6_address_mode') == constants.IPV6_SLAAC):
                continue
            db_subnets[subnet['id']] = subnet

        del_subnet_dhcp_opts_list = []
        for subnet_id, ovn_dhcp_opts in ovn_subnet_dhcp_options.items():
            if subnet_id in db_subnets:
                network = db_networks[utils.ovn_name(
                    db_subnets[subnet_id]['network_id'])]
                if constants.IP_VERSION_6 == db_subnets[subnet_id][
                        'ip_version']:
                    server_mac = ovn_dhcp_opts['options'].get('server_id')
                else:
                    server_mac = ovn_dhcp_opts['options'].get('server_mac')
                dhcp_options = self._ovn_client._get_ovn_dhcp_options(
                    db_subnets[subnet_id], network, server_mac=server_mac)
                # Verify that the cidr and options are also in sync.
                if dhcp_options['cidr'] == ovn_dhcp_opts['cidr'] and (
                        dhcp_options['options'] == ovn_dhcp_opts['options']):
                    del db_subnets[subnet_id]
                else:
                    db_subnets[subnet_id]['ovn_dhcp_options'] = dhcp_options
            else:
                del_subnet_dhcp_opts_list.append(ovn_dhcp_opts)

        for subnet_id, subnet in db_subnets.items():
            LOG.warning('DHCP options for subnet %s is present in '
                        'Neutron but out of sync for OVN', subnet_id)
            if self.mode == SYNC_MODE_REPAIR:
                try:
                    LOG.debug('Adding/Updating DHCP options for subnet %s in '
                              ' OVN NB DB', subnet_id)
                    network = db_networks[utils.ovn_name(subnet['network_id'])]
                    # _ovn_client._add_subnet_dhcp_options doesn't create
                    # a new row in DHCP_Options if the row already exists.
                    # See commands.AddDHCPOptionsCommand.
                    self._ovn_client._add_subnet_dhcp_options(
                        subnet, network, subnet.get('ovn_dhcp_options'))
                except RuntimeError:
                    LOG.warning('Adding/Updating DHCP options for subnet '
                                '%s failed in OVN NB DB', subnet_id)

        txn_commands = []
        for dhcp_opt in del_subnet_dhcp_opts_list:
            LOG.warning('Out of sync subnet DHCP options for subnet %s '
                        'found in OVN NB DB which needs to be deleted',
                        dhcp_opt['external_ids']['subnet_id'])
            if self.mode == SYNC_MODE_REPAIR:
                LOG.debug('Deleting subnet DHCP options for subnet %s ',
                          dhcp_opt['external_ids']['subnet_id'])
                txn_commands.append(self.ovn_api.delete_dhcp_options(
                    dhcp_opt['uuid']))

        if txn_commands:
            with self.ovn_api.transaction(check_error=True) as txn:
                for cmd in txn_commands:
                    txn.add(cmd)
        LOG.debug('OVN-NB Sync DHCP options for Neutron subnets finished')

    def _sync_port_dhcp_options(self, ctx, ports_need_sync_dhcp_opts,
                                ovn_port_dhcpv4_opts, ovn_port_dhcpv6_opts):
        LOG.debug('OVN-NB Sync DHCP options for Neutron ports with extra '
                  'dhcp options assigned started')

        txn_commands = []
        lsp_dhcp_key = {constants.IP_VERSION_4: 'dhcpv4_options',
                        constants.IP_VERSION_6: 'dhcpv6_options'}
        ovn_port_dhcp_opts = {constants.IP_VERSION_4: ovn_port_dhcpv4_opts,
                              constants.IP_VERSION_6: ovn_port_dhcpv6_opts}
        for port in ports_need_sync_dhcp_opts:
            if self.mode == SYNC_MODE_REPAIR:
                LOG.debug('Updating DHCP options for port %s in OVN NB DB',
                          port['id'])
                set_lsp = {}
                for ip_v in [constants.IP_VERSION_4, constants.IP_VERSION_6]:
                    dhcp_opts = (
                        self._ovn_client._get_port_dhcp_options(
                            port, ip_v))
                    if not dhcp_opts or 'uuid' in dhcp_opts:
                        # If the Logical_Switch_Port.dhcpv4_options or
                        # dhcpv6_options no longer refers a port dhcp options
                        # created in DHCP_Options earlier, that port dhcp
                        # options will be deleted in the following
                        # ovn_port_dhcp_options handling.
                        set_lsp[lsp_dhcp_key[ip_v]] = [
                            dhcp_opts['uuid']] if dhcp_opts else []
                    else:
                        # If port has extra port dhcp
                        # options, a command will returned by
                        # self._ovn_client._get_port_dhcp_options
                        # to add or update port dhcp options.
                        ovn_port_dhcp_opts[ip_v].pop(port['id'], None)
                        dhcp_options = dhcp_opts['cmd']
                        txn_commands.append(dhcp_options)
                        set_lsp[lsp_dhcp_key[ip_v]] = dhcp_options
                if set_lsp:
                    txn_commands.append(self.ovn_api.set_lswitch_port(
                        lport_name=port['id'], **set_lsp))

        for ip_v in [constants.IP_VERSION_4, constants.IP_VERSION_6]:
            for port_id, dhcp_opt in ovn_port_dhcp_opts[ip_v].items():
                LOG.warning(
                    'Out of sync port DHCPv%(ip_version)d options for '
                    '(subnet %(subnet_id)s port %(port_id)s) found in OVN '
                    'NB DB which needs to be deleted',
                    {'ip_version': ip_v,
                     'subnet_id': dhcp_opt['external_ids']['subnet_id'],
                     'port_id': port_id})

                if self.mode == SYNC_MODE_REPAIR:
                    LOG.debug('Deleting port DHCPv%d options for (subnet %s, '
                              'port %s)', ip_v,
                              dhcp_opt['external_ids']['subnet_id'], port_id)
                    txn_commands.append(self.ovn_api.delete_dhcp_options(
                        dhcp_opt['uuid']))

        if txn_commands:
            with self.ovn_api.transaction(check_error=True) as txn:
                for cmd in txn_commands:
                    txn.add(cmd)
        LOG.debug('OVN-NB Sync DHCP options for Neutron ports with extra '
                  'dhcp options assigned finished')

    def _sync_metadata_ports(self, ctx, db_ports):
        """Ensure metadata ports in all Neutron networks.

        This method will ensure that all networks have one and only one
        metadata port.
        """
        if not ovn_conf.is_ovn_metadata_enabled():
            return
        LOG.debug('OVN sync metadata ports started')
        for net in self.core_plugin.get_networks(ctx):
            metadata_ports = self.core_plugin.get_ports(
                ctx, filters=dict(
                    network_id=[net['id']],
                    device_owner=[constants.DEVICE_OWNER_DISTRIBUTED]))

            if not metadata_ports:
                LOG.warning('Missing metadata port found in Neutron for '
                            'network %s', net['id'])
                if self.mode == SYNC_MODE_REPAIR:
                    try:
                        # Create the missing port in both Neutron and OVN.
                        LOG.warning('Creating missing metadata port in '
                                    'Neutron and OVN for network %s',
                                    net['id'])
                        self._ovn_client.create_metadata_port(ctx, net)
                    except n_exc.IpAddressGenerationFailure:
                        LOG.error('Could not allocate IP addresses for '
                                  'metadata port in network %s', net['id'])
                        continue
            else:
                # Delete all but one DHCP ports. Only one is needed for
                # metadata.
                for port in metadata_ports[1:]:
                    LOG.warning('Unnecessary DHCP port %s for network %s '
                                'found in Neutron', port['id'], net['id'])
                    if self.mode == SYNC_MODE_REPAIR:
                        LOG.warning('Deleting unnecessary DHCP port %s for '
                                    'network %s', port['id'], net['id'])
                        self.core_plugin.delete_port(ctx, port['id'])
                    db_ports.pop(port['id'], None)
                port = metadata_ports[0]
                if port['id'] in db_ports.keys():
                    LOG.warning('Metadata port %s for network %s found in '
                                'Neutron but not in OVN',
                                port['id'], net['id'])
                    if self.mode == SYNC_MODE_REPAIR:
                        LOG.warning('Creating metadata port %s for network '
                                    '%s in OVN',
                                    port['id'], net['id'])
                        self._create_port_in_ovn(ctx, port)
                    db_ports.pop(port['id'])

            if self.mode == SYNC_MODE_REPAIR:
                try:
                    # Make sure that this port has an IP address in all the
                    # subnets
                    self._ovn_client.update_metadata_port(ctx, net['id'])
                except n_exc.IpAddressGenerationFailure:
                    LOG.error('Could not allocate IP addresses for '
                              'metadata port in network %s', net['id'])
        LOG.debug('OVN sync metadata ports finished')

    def sync_networks_ports_and_dhcp_opts(self, ctx):
        LOG.debug('OVN-NB Sync networks, ports and DHCP options started')
        db_networks = {}
        for net in self.core_plugin.get_networks(ctx):
            db_networks[utils.ovn_name(net['id'])] = net

        # Ignore the floating ip ports with device_owner set to
        # constants.DEVICE_OWNER_FLOATINGIP
        db_ports = {port['id']: port for port in
                    self.core_plugin.get_ports(ctx) if not
                    utils.is_lsp_ignored(port)}

        ovn_all_dhcp_options = self.ovn_api.get_all_dhcp_options()
        db_network_cache = dict(db_networks)

        ports_need_sync_dhcp_opts = []
        lswitches = self.ovn_api.get_all_logical_switches_with_ports()
        del_lswitchs_list = []
        del_lports_list = []
        add_provnet_ports_list = []
        del_provnet_ports_list = []
        for lswitch in lswitches:
            if lswitch['name'] in db_networks:
                for lport in lswitch['ports']:
                    if lport in db_ports:
                        port = db_ports.pop(lport)
                        if not utils.is_network_device_port(port):
                            ports_need_sync_dhcp_opts.append(port)
                    else:
                        del_lports_list.append({'port': lport,
                                                'lswitch': lswitch['name']})
                db_network = db_networks[lswitch['name']]
                db_segments = self.segments_plugin.get_segments(
                    ctx, filters={'network_id': [db_network['id']]})
                segments_provnet_port_names = []
                for db_segment in db_segments:
                    physnet = db_segment.get(segment_def.PHYSICAL_NETWORK)
                    pname = utils.ovn_provnet_port_name(db_segment['id'])
                    segments_provnet_port_names.append(pname)
                    if physnet and pname not in lswitch['provnet_ports']:
                        add_provnet_ports_list.append(
                            {'network': db_network,
                             'segment': db_segment,
                             'lswitch': lswitch['name']})
                # Delete orphaned provnet ports
                for provnet_port in lswitch['provnet_ports']:
                    if provnet_port in segments_provnet_port_names:
                        continue
                    if provnet_port not in [
                            utils.ovn_provnet_port_name(v['segment'])
                            for v in add_provnet_ports_list]:
                        del_provnet_ports_list.append(
                            {'network': db_network,
                             'lport': provnet_port,
                             'lswitch': lswitch['name']})

                del db_networks[lswitch['name']]
            else:
                del_lswitchs_list.append(lswitch)

        for net_id, network in db_networks.items():
            LOG.warning("Network found in Neutron but not in "
                        "OVN DB, network_id=%s", network['id'])
            if self.mode == SYNC_MODE_REPAIR:
                try:
                    LOG.debug('Creating the network %s in OVN NB DB',
                              network['id'])
                    self._ovn_client.create_network(ctx, network)
                except RuntimeError:
                    LOG.warning("Create network in OVN NB failed for "
                                "network %s", network['id'])

        self._sync_metadata_ports(ctx, db_ports)

        self._sync_subnet_dhcp_options(
            ctx, db_network_cache, ovn_all_dhcp_options['subnets'])

        for port_id, port in db_ports.items():
            LOG.warning("Port found in Neutron but not in OVN "
                        "DB, port_id=%s", port['id'])
            if self.mode == SYNC_MODE_REPAIR:
                try:
                    LOG.debug('Creating the port %s in OVN NB DB',
                              port['id'])
                    self._create_port_in_ovn(ctx, port)
                    if port_id in ovn_all_dhcp_options['ports_v4']:
                        dhcp_disable, lsp_opts = utils.get_lsp_dhcp_opts(
                            port, constants.IP_VERSION_4)
                        if lsp_opts:
                            ovn_all_dhcp_options['ports_v4'].pop(port_id)
                    if port_id in ovn_all_dhcp_options['ports_v6']:
                        dhcp_disable, lsp_opts = utils.get_lsp_dhcp_opts(
                            port, constants.IP_VERSION_6)
                        if lsp_opts:
                            ovn_all_dhcp_options['ports_v6'].pop(port_id)
                except RuntimeError:
                    LOG.warning("Create port in OVN NB failed for"
                                " port %s", port['id'])

        with self.ovn_api.transaction(check_error=True) as txn:
            for lswitch in del_lswitchs_list:
                LOG.warning("Network found in OVN but not in "
                            "Neutron, network_id=%s", lswitch['name'])
                if self.mode == SYNC_MODE_REPAIR:
                    LOG.debug('Deleting the network %s from OVN NB DB',
                              lswitch['name'])
                    txn.add(self.ovn_api.ls_del(lswitch['name']))

            for provnet_port_info in add_provnet_ports_list:
                network = provnet_port_info['network']
                segment = provnet_port_info['segment']
                LOG.warning("Provider network found in Neutron but "
                            "provider network port not found in OVN DB, "
                            "network_id=%(net)s segment_id=%(seg)s",
                            {'net': network['id'],
                             'seg': segment['id']})
                if self.mode == SYNC_MODE_REPAIR:
                    LOG.debug('Creating the provnet port %s in OVN NB DB',
                              utils.ovn_provnet_port_name(segment['id']))
                    self._ovn_client.create_provnet_port(
                        network['id'], segment, txn=txn)

            for provnet_port_info in del_provnet_ports_list:
                network = provnet_port_info['network']
                lport = provnet_port_info['lport']
                lswitch = provnet_port_info['lswitch']
                LOG.warning("Provider network port found in OVN DB, "
                            "but not in neutron network_id=%(net)s "
                            "port_name=%(lport)s",
                            {'net': network,
                             'seg': lport})
                if self.mode == SYNC_MODE_REPAIR:
                    LOG.debug('Deleting the port %s from OVN NB DB',
                              lport)
                    txn.add(self.ovn_api.delete_lswitch_port(
                        lport_name=lport,
                        lswitch_name=lswitch))

            for lport_info in del_lports_list:
                LOG.warning("Port found in OVN but not in "
                            "Neutron, port_id=%s", lport_info['port'])
                if self.mode == SYNC_MODE_REPAIR:
                    LOG.debug('Deleting the port %s from OVN NB DB',
                              lport_info['port'])
                    txn.add(self.ovn_api.delete_lswitch_port(
                        lport_name=lport_info['port'],
                        lswitch_name=lport_info['lswitch']))
                    if lport_info['port'] in ovn_all_dhcp_options['ports_v4']:
                        LOG.debug('Deleting port DHCPv4 options for (port %s)',
                                  lport_info['port'])
                        txn.add(self.ovn_api.delete_dhcp_options(
                            ovn_all_dhcp_options['ports_v4'].pop(
                                lport_info['port'])['uuid']))
                    if lport_info['port'] in ovn_all_dhcp_options['ports_v6']:
                        LOG.debug('Deleting port DHCPv6 options for (port %s)',
                                  lport_info['port'])
                        txn.add(self.ovn_api.delete_dhcp_options(
                            ovn_all_dhcp_options['ports_v6'].pop(
                                lport_info['port'])['uuid']))

        self._sync_port_dhcp_options(ctx, ports_need_sync_dhcp_opts,
                                     ovn_all_dhcp_options['ports_v4'],
                                     ovn_all_dhcp_options['ports_v6'])
        LOG.debug('OVN-NB Sync networks, ports and DHCP options finished')

    def sync_port_dns_records(self, ctx):
        if self.mode != SYNC_MODE_REPAIR:
            return
        LOG.debug('OVN-NB Sync port dns records')
        # Ignore the floating ip ports with device_owner set to
        # constants.DEVICE_OWNER_FLOATINGIP
        db_ports = [port for port in
                    self.core_plugin.get_ports(ctx) if not
                    port.get('device_owner', '').startswith(
                        constants.DEVICE_OWNER_FLOATINGIP)]
        dns_records = {}
        for port in db_ports:
            if self._ovn_client.is_dns_required_for_port(port):
                port_dns_records = self._ovn_client.get_port_dns_records(port)
                if port['network_id'] not in dns_records:
                    dns_records[port['network_id']] = {}
                dns_records[port['network_id']].update(port_dns_records)

        for network_id, port_dns_records in dns_records.items():
            self._set_dns_records(network_id, port_dns_records)

    def _set_dns_records(self, network_id, dns_records):
        lswitch_name = utils.ovn_name(network_id)
        ls, ls_dns_record = self.ovn_api.get_ls_and_dns_record(lswitch_name)

        with self.ovn_api.transaction(check_error=True) as txn:
            if not ls_dns_record:
                dns_add_txn = txn.add(self.ovn_api.dns_add(
                    external_ids={'ls_name': ls.name}, records=dns_records))
                txn.add(self.ovn_api.ls_set_dns_records(ls.uuid, dns_add_txn))
            else:
                txn.add(self.ovn_api.dns_set_records(ls_dns_record.uuid,
                                                     **dns_records))

    def _delete_address_sets(self, ctx):
        with self.ovn_api.transaction(check_error=True) as txn:
            for sg in self.core_plugin.get_security_groups(ctx):
                for ip_version in ['ip4', 'ip6']:
                    txn.add(self.ovn_api.delete_address_set(
                        utils.ovn_addrset_name(sg['id'], ip_version)))

    def _delete_acls_from_lswitches(self, ctx):
        with self.ovn_api.transaction(check_error=True) as txn:
            for net in self.core_plugin.get_networks(ctx):
                # Calling acl_del from ovsdbapp with no ACL will delete
                # all the ACLs belonging to that Logical Switch.
                txn.add(self.ovn_api.acl_del(utils.ovn_name(net['id'])))

    def _create_sg_port_groups_and_acls(self, ctx, db_ports):
        # Create a Port Group per Neutron Security Group
        with self.ovn_api.transaction(check_error=True) as txn:
            for sg in self.core_plugin.get_security_groups(ctx):
                pg_name = utils.ovn_port_group_name(sg['id'])
                if self.ovn_api.get_port_group(pg_name):
                    continue
                ext_ids = {ovn_const.OVN_SG_EXT_ID_KEY: sg['id']}
                txn.add(self.ovn_api.pg_add(
                    name=pg_name, acls=[], external_ids=ext_ids))
                acl_utils.add_acls_for_sg_port_group(
                    self.ovn_api, sg, txn,
                    self._ovn_client.is_allow_stateless_supported())
            for port in db_ports:
                for sg in port['security_groups']:
                    txn.add(self.ovn_api.pg_add_ports(
                        utils.ovn_port_group_name(sg), port['id']))

    def migrate_to_stateful_fips(self, ctx):
        # This routine will clear options:stateless=true for all dnat_and_snats
        # that belong to neutron fips. Since we don't set any other options,
        # just clear the whole column.
        with self.ovn_api.transaction(check_error=True) as txn:
            for nat in self.ovn_api.get_all_stateless_fip_nats():
                txn.add(self.ovn_api.db_clear('NAT', nat['_uuid'], 'options'))

    def migrate_to_port_groups(self, ctx):
        # This routine is responsible for migrating the current Security
        # Groups and SG Rules to the new Port Groups implementation.
        # 1. Create a Port Group for every existing Neutron Security Group and
        #    add all its Security Group Rules as ACLs to that Port Group.
        # 2. Delete all existing Address Sets in NorthBound database which
        #    correspond to a Neutron Security Group.
        # 3. Delete all the ACLs in every Logical Switch (Neutron network).

        # If we've already migrated, return
        if not self.ovn_api.get_address_sets():
            return

        LOG.debug('Port Groups Migration task started')

        # Ignore the floating ip ports with device_owner set to
        # constants.DEVICE_OWNER_FLOATINGIP
        db_ports = [port for port in
                    self.core_plugin.get_ports(ctx) if not
                    utils.is_lsp_ignored(port) and not
                    utils.is_lsp_trusted(port) and
                    utils.is_port_security_enabled(port)]

        self._create_sg_port_groups_and_acls(ctx, db_ports)
        self._delete_address_sets(ctx)
        self._delete_acls_from_lswitches(ctx)

        LOG.debug('Port Groups Migration task finished')

    def sync_port_qos_policies(self, ctx):
        """Sync port QoS policies.

        This method reads the port QoS policy assigned or the one inherited
        from the network. Does not apply to "network" owned ports.
        """
        LOG.debug('Port QoS policies migration task started')
        ovn_qos_ext = ovn_qos.OVNClientQosExtension(nb_idl=self.ovn_api)
        with db_api.CONTEXT_READER.using(ctx), \
                self.ovn_api.transaction(check_error=True) as txn:
            for port in self.core_plugin.get_ports(ctx):
                if not ovn_qos_ext.port_effective_qos_policy_id(port)[0]:
                    continue
                ovn_qos_ext.create_port(txn, port, None)

        LOG.debug('Port QoS policies migration task finished')

    def sync_fip_qos_policies(self, ctx):
        """Sync floating IP QoS policies."""
        LOG.debug('Floating IP QoS policies migration task started')
        ovn_qos_ext = ovn_qos.OVNClientQosExtension(nb_idl=self.ovn_api)
        with db_api.CONTEXT_READER.using(ctx), \
                self.ovn_api.transaction(check_error=True) as txn:
            for fip in self.l3_plugin.get_floatingips(ctx):
                if not fip.get('qos_policy_id'):
                    continue
                ovn_qos_ext.create_floatingip(txn, fip)

        LOG.debug('Floating IP QoS policies migration task finished')


class OvnSbSynchronizer(OvnDbSynchronizer):
    """Synchronizer class for SB."""

    def __init__(self, core_plugin, ovn_api, ovn_driver):
        super(OvnSbSynchronizer, self).__init__(
            core_plugin, ovn_api, ovn_driver)
        self.l3_plugin = directory.get_plugin(plugin_constants.L3)

    def do_sync(self):
        """Method to sync the OVN_Southbound DB with neutron DB.

        OvnSbSynchronizer will sync data from OVN_Southbound to neutron. And
        the synchronization will always be performed, no matter what mode it
        is.
        """
        LOG.debug("Starting OVN-Southbound DB sync process")

        ctx = context.get_admin_context()
        self.sync_hostname_and_physical_networks(ctx)
        if utils.is_ovn_l3(self.l3_plugin):
            self.l3_plugin.schedule_unhosted_gateways()
        # NOTE(ralonsoh): this could be called using a resource event.
        self.ovn_driver._ovn_client.placement_extension.\
            read_initial_chassis_config()

    def sync_hostname_and_physical_networks(self, ctx):
        LOG.debug('OVN-SB Sync hostname and physical networks started')
        host_phynets_map = self.ovn_api.get_chassis_hostname_and_physnets()
        current_hosts = set(host_phynets_map)
        previous_hosts = segments_db.get_hosts_mapped_with_segments(ctx)

        stale_hosts = previous_hosts - current_hosts
        for host in stale_hosts:
            LOG.debug('Stale host %s found in Neutron, but not in OVN SB DB. '
                      'Clear its SegmentHostMapping in Neutron', host)
            self.ovn_driver.update_segment_host_mapping(host, [])

        new_hosts = current_hosts - previous_hosts
        for host in new_hosts:
            LOG.debug('New host %s found in OVN SB DB, but not in Neutron. '
                      'Add its SegmentHostMapping in Neutron', host)
            self.ovn_driver.update_segment_host_mapping(
                host, host_phynets_map[host])

        for host in current_hosts & previous_hosts:
            LOG.debug('Host %s found both in OVN SB DB and Neutron. '
                      'Trigger updating its SegmentHostMapping in Neutron, '
                      'to keep OVN SB DB and Neutron have consistent data',
                      host)
            self.ovn_driver.update_segment_host_mapping(
                host, host_phynets_map[host])

        LOG.debug('OVN-SB Sync hostname and physical networks finished')

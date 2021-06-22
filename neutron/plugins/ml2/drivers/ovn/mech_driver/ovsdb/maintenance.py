# Copyright 2019 Red Hat, Inc.
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

import abc
import inspect
import threading

from futurist import periodics
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import segment as segment_def
from neutron_lib import constants as n_const
from neutron_lib import context as n_context
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log
from oslo_utils import timeutils
from ovsdbapp.backend.ovs_idl import event as row_event

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.db import ovn_hash_ring_db as hash_ring_db
from neutron.db import ovn_revision_numbers_db as revision_numbers_db
from neutron.db import segments_db
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_db_sync


CONF = cfg.CONF
LOG = log.getLogger(__name__)

DB_CONSISTENCY_CHECK_INTERVAL = 300  # 5 minutes
INCONSISTENCY_TYPE_CREATE_UPDATE = 'create/update'
INCONSISTENCY_TYPE_DELETE = 'delete'


class MaintenanceThread(object):

    def __init__(self):
        self._callables = []
        self._thread = None
        self._worker = None

    def add_periodics(self, obj):
        for name, member in inspect.getmembers(obj):
            if periodics.is_periodic(member):
                LOG.debug('Periodic task found: %(owner)s.%(member)s',
                          {'owner': obj.__class__.__name__, 'member': name})
                self._callables.append((member, (), {}))

    def start(self):
        if self._thread is None:
            self._worker = periodics.PeriodicWorker(self._callables)
            self._thread = threading.Thread(target=self._worker.start)
            self._thread.daemon = True
            self._thread.start()

    def stop(self):
        self._worker.stop()
        self._worker.wait()
        self._thread.join()
        self._worker = self._thread = None


def rerun_on_schema_updates(func):
    """Tasks decorated with this will rerun upon database version updates."""
    func._rerun_on_schema_updates = True
    return func


class OVNNBDBReconnectionEvent(row_event.RowEvent):
    """Event listening to reconnections from OVN Northbound DB."""

    def __init__(self, driver, version):
        self.driver = driver
        self.version = version
        table = 'Connection'
        events = (self.ROW_CREATE,)
        super(OVNNBDBReconnectionEvent, self).__init__(events, table, None)
        self.event_name = self.__class__.__name__

    def run(self, event, row, old):
        curr_version = self.driver.get_ovn_nbdb_version()
        if self.version != curr_version:
            self.driver.nbdb_schema_updated_hook()
            self.version = curr_version


class SchemaAwarePeriodicsBase(object):

    def __init__(self, ovn_client):
        self._nb_idl = ovn_client._nb_idl
        self._set_schema_aware_periodics()
        self._nb_idl.idl.notify_handler.watch_event(OVNNBDBReconnectionEvent(
            self, self.get_ovn_nbdb_version()))

    def get_ovn_nbdb_version(self):
        return self._nb_idl.idl._db.version

    def _set_schema_aware_periodics(self):
        self._schema_aware_periodics = []
        for name, member in inspect.getmembers(self):
            if not inspect.ismethod(member):
                continue

            schema_upt = getattr(member, '_rerun_on_schema_updates', None)
            if schema_upt and periodics.is_periodic(member):
                LOG.debug('Schema aware periodic task found: '
                          '%(owner)s.%(member)s',
                          {'owner': self.__class__.__name__, 'member': name})
                self._schema_aware_periodics.append(member)

    @abc.abstractmethod
    def nbdb_schema_updated_hook(self):
        """Hook invoked upon OVN NB schema is updated."""


class DBInconsistenciesPeriodics(SchemaAwarePeriodicsBase):

    def __init__(self, ovn_client):
        self._ovn_client = ovn_client
        # FIXME(lucasagomes): We should not be accessing private
        # attributes like that, perhaps we should extend the OVNClient
        # class and create an interface for the locks ?
        self._nb_idl = self._ovn_client._nb_idl
        self._sb_idl = self._ovn_client._sb_idl
        self._idl = self._nb_idl.idl
        self._idl.set_lock('ovn_db_inconsistencies_periodics')
        self._sync_timer = timeutils.StopWatch()
        super(DBInconsistenciesPeriodics, self).__init__(ovn_client)

        self._resources_func_map = {
            ovn_const.TYPE_NETWORKS: {
                'neutron_get': self._ovn_client._plugin.get_network,
                'ovn_get': self._nb_idl.get_lswitch,
                'ovn_create': self._ovn_client.create_network,
                'ovn_update': self._ovn_client.update_network,
                'ovn_delete': self._ovn_client.delete_network,
            },
            ovn_const.TYPE_PORTS: {
                'neutron_get': self._ovn_client._plugin.get_port,
                'ovn_get': self._nb_idl.get_lswitch_port,
                'ovn_create': self._ovn_client.create_port,
                'ovn_update': self._ovn_client.update_port,
                'ovn_delete': self._ovn_client.delete_port,
            },
            ovn_const.TYPE_FLOATINGIPS: {
                'neutron_get': self._ovn_client._l3_plugin.get_floatingip,
                'ovn_get': self._nb_idl.get_floatingip_in_nat_or_lb,
                'ovn_create': self._create_floatingip_and_pf,
                'ovn_update': self._update_floatingip_and_pf,
                'ovn_delete': self._delete_floatingip_and_pf,
            },
            ovn_const.TYPE_ROUTERS: {
                'neutron_get': self._ovn_client._l3_plugin.get_router,
                'ovn_get': self._nb_idl.get_lrouter,
                'ovn_create': self._ovn_client.create_router,
                'ovn_update': self._ovn_client.update_router,
                'ovn_delete': self._ovn_client.delete_router,
            },
            ovn_const.TYPE_SECURITY_GROUPS: {
                'neutron_get': self._ovn_client._plugin.get_security_group,
                'ovn_get': self._nb_idl.get_port_group,
                'ovn_create': self._ovn_client.create_security_group,
                'ovn_delete': self._ovn_client.delete_security_group,
            },
            ovn_const.TYPE_SECURITY_GROUP_RULES: {
                'neutron_get':
                    self._ovn_client._plugin.get_security_group_rule,
                'ovn_get': self._nb_idl.get_acl_by_id,
                'ovn_create': self._ovn_client.create_security_group_rule,
                'ovn_delete': self._ovn_client.delete_security_group_rule,
            },
            ovn_const.TYPE_ROUTER_PORTS: {
                'neutron_get':
                    self._ovn_client._plugin.get_port,
                'ovn_get': self._nb_idl.get_lrouter_port,
                'ovn_create': self._create_lrouter_port,
                'ovn_update': self._ovn_client.update_router_port,
                'ovn_delete': self._ovn_client.delete_router_port,
            },
        }

    @property
    def has_lock(self):
        return not self._idl.is_lock_contended

    def nbdb_schema_updated_hook(self):
        if not self.has_lock:
            return

        for func in self._schema_aware_periodics:
            LOG.debug('OVN Northbound DB schema version was updated,'
                      'invoking "%s"', func.__name__)
            try:
                func()
            except periodics.NeverAgain:
                pass
            except Exception:
                LOG.exception(
                    'Unknown error while executing "%s"', func.__name__)

    def _fix_create_update(self, context, row):
        res_map = self._resources_func_map[row.resource_type]
        try:
            # Get the latest version of the resource in Neutron DB
            n_obj = res_map['neutron_get'](context, row.resource_uuid)
        except n_exc.NotFound:
            LOG.warning('Skip fixing resource %(res_uuid)s (type: '
                        '%(res_type)s). Resource does not exist in Neutron '
                        'database anymore', {'res_uuid': row.resource_uuid,
                                             'res_type': row.resource_type})
            return

        ovn_obj = res_map['ovn_get'](row.resource_uuid)

        if not ovn_obj:
            res_map['ovn_create'](context, n_obj)
        else:
            if row.resource_type == ovn_const.TYPE_SECURITY_GROUP_RULES:
                LOG.error("SG rule %s found with a revision number while "
                          "this resource doesn't support updates",
                          row.resource_uuid)
            elif row.resource_type == ovn_const.TYPE_SECURITY_GROUPS:
                # In OVN, we don't care about updates to security groups,
                # so just bump the revision number to whatever it's
                # supposed to be.
                revision_numbers_db.bump_revision(context, n_obj,
                                                  row.resource_type)
            else:
                ext_ids = getattr(ovn_obj, 'external_ids', {})
                ovn_revision = int(ext_ids.get(
                    ovn_const.OVN_REV_NUM_EXT_ID_KEY, -1))
                # If the resource exist in the OVN DB but the revision
                # number is different from Neutron DB, updated it.
                if ovn_revision != n_obj['revision_number']:
                    res_map['ovn_update'](context, n_obj)
                else:
                    # If the resource exist and the revision number
                    # is equal on both databases just bump the revision on
                    # the cache table.
                    revision_numbers_db.bump_revision(context, n_obj,
                                                      row.resource_type)

    def _fix_delete(self, context, row):
        res_map = self._resources_func_map[row.resource_type]
        ovn_obj = res_map['ovn_get'](row.resource_uuid)
        if not ovn_obj:
            revision_numbers_db.delete_revision(
                context, row.resource_uuid, row.resource_type)
        else:
            res_map['ovn_delete'](context, row.resource_uuid)

    def _fix_create_update_subnet(self, context, row):
        # Get the lasted version of the port in Neutron DB
        sn_db_obj = self._ovn_client._plugin.get_subnet(
            context, row.resource_uuid)
        n_db_obj = self._ovn_client._plugin.get_network(
            context, sn_db_obj['network_id'])

        if row.revision_number == ovn_const.INITIAL_REV_NUM:
            self._ovn_client.create_subnet(context, sn_db_obj, n_db_obj)
        else:
            self._ovn_client.update_subnet(context, sn_db_obj, n_db_obj)

    # The migration will run just once per neutron-server instance. If the lock
    # is held by some other neutron-server instance in the cloud, we'll attempt
    # to perform the migration every 10 seconds until completed.
    # TODO(jlibosva): Remove the migration to port groups at some point. It's
    # been around since Queens release so it is good to drop this soon.
    @periodics.periodic(spacing=10, run_immediately=True)
    @rerun_on_schema_updates
    def migrate_to_port_groups(self):
        """Perform the migration from Address Sets to Port Groups. """
        # TODO(dalvarez): Remove this in U cycle when we're sure that all
        # versions are running using Port Groups (and OVS >= 2.10).

        # If Port Groups are not supported or we've already migrated, we don't
        # need to attempt to migrate again.
        if not self._nb_idl.get_address_sets():
            raise periodics.NeverAgain()

        # Only the worker holding a valid lock within OVSDB will perform the
        # migration.
        if not self.has_lock:
            return

        admin_context = n_context.get_admin_context()
        nb_sync = ovn_db_sync.OvnNbSynchronizer(
            self._ovn_client._plugin, self._nb_idl, self._ovn_client._sb_idl,
            None, None)
        nb_sync.migrate_to_port_groups(admin_context)
        raise periodics.NeverAgain()

    def _log_maintenance_inconsistencies(self, create_update_inconsistencies,
                                         delete_inconsistencies):
        if not CONF.debug:
            return

        def _log(inconsistencies, type_):
            if not inconsistencies:
                return

            c = {}
            for f in inconsistencies:
                if f.resource_type not in c:
                    c[f.resource_type] = 1
                else:
                    c[f.resource_type] += 1

            fail_str = ', '.join('{}={}'.format(k, v) for k, v in c.items())
            LOG.debug('Maintenance task: Number of inconsistencies '
                      'found at %(type_)s: %(fail_str)s',
                      {'type_': type_, 'fail_str': fail_str})

        _log(create_update_inconsistencies, INCONSISTENCY_TYPE_CREATE_UPDATE)
        _log(delete_inconsistencies, INCONSISTENCY_TYPE_DELETE)

    @periodics.periodic(spacing=DB_CONSISTENCY_CHECK_INTERVAL,
                        run_immediately=True)
    def check_for_inconsistencies(self):
        # Only the worker holding a valid lock within OVSDB will run
        # this periodic
        if not self.has_lock:
            return

        admin_context = n_context.get_admin_context()
        create_update_inconsistencies = (
            revision_numbers_db.get_inconsistent_resources(admin_context))
        delete_inconsistencies = (
            revision_numbers_db.get_deleted_resources(admin_context))
        if not any([create_update_inconsistencies, delete_inconsistencies]):
            LOG.debug('Maintenance task: No inconsistencies found. Skipping')
            return

        LOG.debug('Maintenance task: Synchronizing Neutron '
                  'and OVN databases')
        self._log_maintenance_inconsistencies(create_update_inconsistencies,
                                              delete_inconsistencies)
        self._sync_timer.restart()

        dbg_log_msg = ('Maintenance task: Fixing resource %(res_uuid)s '
                       '(type: %(res_type)s) at %(type_)s')
        # Fix the create/update resources inconsistencies
        for row in create_update_inconsistencies:
            LOG.debug(dbg_log_msg, {'res_uuid': row.resource_uuid,
                                    'res_type': row.resource_type,
                                    'type_': INCONSISTENCY_TYPE_CREATE_UPDATE})
            try:
                # NOTE(lucasagomes): The way to fix subnets is bit
                # different than other resources. A subnet in OVN language
                # is just a DHCP rule but, this rule only exist if the
                # subnet in Neutron has the "enable_dhcp" attribute set
                # to True. So, it's possible to have a consistent subnet
                # resource even when it does not exist in the OVN database.
                if row.resource_type == ovn_const.TYPE_SUBNETS:
                    self._fix_create_update_subnet(admin_context, row)
                else:
                    self._fix_create_update(admin_context, row)
            except Exception:
                LOG.exception('Maintenance task: Failed to fix resource '
                              '%(res_uuid)s (type: %(res_type)s)',
                              {'res_uuid': row.resource_uuid,
                               'res_type': row.resource_type})

        # Fix the deleted resources inconsistencies
        for row in delete_inconsistencies:
            LOG.debug(dbg_log_msg, {'res_uuid': row.resource_uuid,
                                    'res_type': row.resource_type,
                                    'type_': INCONSISTENCY_TYPE_DELETE})
            try:
                if row.resource_type == ovn_const.TYPE_SUBNETS:
                    self._ovn_client.delete_subnet(admin_context,
                                                   row.resource_uuid)
                else:
                    self._fix_delete(admin_context, row)
            except Exception:
                LOG.exception('Maintenance task: Failed to fix deleted '
                              'resource %(res_uuid)s (type: %(res_type)s)',
                              {'res_uuid': row.resource_uuid,
                               'res_type': row.resource_type})

        self._sync_timer.stop()
        LOG.info('Maintenance task: Synchronization finished '
                 '(took %.2f seconds)', self._sync_timer.elapsed())

    def _create_lrouter_port(self, context, port):
        router_id = port['device_id']
        iface_info = self._ovn_client._l3_plugin._add_neutron_router_interface(
            context, router_id, {'port_id': port['id']}, may_exist=True)
        self._ovn_client.create_router_port(context, router_id, iface_info)

    def _check_subnet_global_dhcp_opts(self):
        inconsistent_subnets = []
        admin_context = n_context.get_admin_context()
        subnet_filter = {'enable_dhcp': [True]}
        neutron_subnets = self._ovn_client._plugin.get_subnets(
            admin_context, subnet_filter)
        global_v4_opts = ovn_conf.get_global_dhcpv4_opts()
        global_v6_opts = ovn_conf.get_global_dhcpv6_opts()
        LOG.debug('Checking %s subnets for global DHCP option consistency',
                  len(neutron_subnets))
        for subnet in neutron_subnets:
            ovn_dhcp_opts = self._nb_idl.get_subnet_dhcp_options(
                subnet['id'])['subnet']
            inconsistent_opts = []
            if ovn_dhcp_opts:
                if subnet['ip_version'] == n_const.IP_VERSION_4:
                    for opt, value in global_v4_opts.items():
                        if value != ovn_dhcp_opts['options'].get(opt, None):
                            inconsistent_opts.append(opt)
                if subnet['ip_version'] == n_const.IP_VERSION_6:
                    for opt, value in global_v6_opts.items():
                        if value != ovn_dhcp_opts['options'].get(opt, None):
                            inconsistent_opts.append(opt)
            if inconsistent_opts:
                LOG.debug('Subnet %s has inconsistent DHCP opts: %s',
                          subnet['id'], inconsistent_opts)
                inconsistent_subnets.append(subnet)
        return inconsistent_subnets

    def _create_floatingip_and_pf(self, context, floatingip):
        self._ovn_client.create_floatingip(context, floatingip)
        self._ovn_client._l3_plugin.port_forwarding.maintenance_create(
            context, floatingip)

    def _update_floatingip_and_pf(self, context, floatingip):
        self._ovn_client.update_floatingip(context, floatingip)
        self._ovn_client._l3_plugin.port_forwarding.maintenance_update(
            context, floatingip)

    def _delete_floatingip_and_pf(self, context, fip_id):
        self._ovn_client._l3_plugin.port_forwarding.maintenance_delete(
            context, fip_id)
        self._ovn_client.delete_floatingip(context, fip_id)

    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @periodics.periodic(spacing=600,
                        run_immediately=True)
    def check_global_dhcp_opts(self):
        # This periodic task is included in DBInconsistenciesPeriodics since
        # it uses the lock to ensure only one worker is executing
        if not self.has_lock:
            return
        if (not ovn_conf.get_global_dhcpv4_opts() and
                not ovn_conf.get_global_dhcpv6_opts()):
            # No need to scan the subnets if the settings are unset.
            raise periodics.NeverAgain()
        LOG.debug('Maintenance task: Checking DHCP options on subnets')
        self._sync_timer.restart()
        fix_subnets = self._check_subnet_global_dhcp_opts()
        if fix_subnets:
            admin_context = n_context.get_admin_context()
            LOG.debug('Triggering update for %s subnets', len(fix_subnets))
            for subnet in fix_subnets:
                neutron_net = self._ovn_client._plugin.get_network(
                    admin_context, subnet['network_id'])
                try:
                    self._ovn_client.update_subnet(admin_context, subnet,
                                                   neutron_net)
                except Exception:
                    LOG.exception('Failed to update subnet %s',
                                  subnet['id'])

        self._sync_timer.stop()
        LOG.info('Maintenance task: DHCP options check finished '
                 '(took %.2f seconds)', self._sync_timer.elapsed())

        raise periodics.NeverAgain()

    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @periodics.periodic(spacing=1800, run_immediately=True)
    def check_metadata_ports(self):
        # If OVN metadata is disabled do not run this task again
        if not ovn_conf.is_ovn_metadata_enabled():
            raise periodics.NeverAgain()

        # Make sure that only one worker is executing this
        if not self.has_lock:
            return

        admin_context = n_context.get_admin_context()
        for n in self._ovn_client._plugin.get_networks(admin_context):
            self._ovn_client.create_metadata_port(admin_context, n)

        raise periodics.NeverAgain()

    # TODO(lucasagomes): Remove this in the U cycle
    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @periodics.periodic(spacing=600, run_immediately=True)
    def check_for_port_security_unknown_address(self):

        if not self.has_lock:
            return

        for port in self._nb_idl.lsp_list().execute(check_error=True):

            if port.type == ovn_const.LSP_TYPE_LOCALNET:
                continue

            addresses = port.addresses
            type_ = port.type.strip()
            if not port.port_security:
                if not type_ and ovn_const.UNKNOWN_ADDR not in addresses:
                    addresses.append(ovn_const.UNKNOWN_ADDR)
                elif type_ and ovn_const.UNKNOWN_ADDR in addresses:
                    addresses.remove(ovn_const.UNKNOWN_ADDR)
            else:
                if type_ and ovn_const.UNKNOWN_ADDR in addresses:
                    addresses.remove(ovn_const.UNKNOWN_ADDR)
                elif not type_ and ovn_const.UNKNOWN_ADDR in addresses:
                    addresses.remove(ovn_const.UNKNOWN_ADDR)

            if addresses:
                self._nb_idl.lsp_set_addresses(
                    port.name, addresses=addresses).execute(check_error=True)
            else:
                self._nb_idl.db_clear(
                    'Logical_Switch_Port', port.name,
                    'addresses').execute(check_error=True)

        raise periodics.NeverAgain()

    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @periodics.periodic(spacing=600, run_immediately=True)
    def check_for_fragmentation_support(self):
        if not self.has_lock:
            return

        context = n_context.get_admin_context()
        for net in self._ovn_client._plugin.get_networks(
                context, {external_net.EXTERNAL: [True]}):
            self._ovn_client.set_gateway_mtu(context, net)

        raise periodics.NeverAgain()

    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @periodics.periodic(spacing=600, run_immediately=True)
    def check_for_igmp_snoop_support(self):
        if not self.has_lock:
            return

        with self._nb_idl.transaction(check_error=True) as txn:
            value = ('true' if ovn_conf.is_igmp_snooping_enabled()
                     else 'false')
            for ls in self._nb_idl.ls_list().execute(check_error=True):
                if ls.other_config.get(ovn_const.MCAST_SNOOP, None) == value:
                    continue
                txn.add(self._nb_idl.db_set(
                    'Logical_Switch', ls.name,
                    ('other_config', {
                        ovn_const.MCAST_SNOOP: value,
                        ovn_const.MCAST_FLOOD_UNREGISTERED: 'false'})))

        raise periodics.NeverAgain()

    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @periodics.periodic(spacing=600, run_immediately=True)
    def check_for_ha_chassis_group_address(self):
        # If external ports is not supported stop running
        # this periodic task
        if not self._ovn_client.is_external_ports_supported():
            raise periodics.NeverAgain()

        if not self.has_lock:
            return

        default_ch_grp = self._nb_idl.ha_chassis_group_add(
            ovn_const.HA_CHASSIS_GROUP_DEFAULT_NAME, may_exist=True).execute(
            check_error=True)

        # NOTE(lucasagomes): Find the existing chassis with the highest
        # priority and keep it as being the highest to avoid moving
        # things around
        high_prio_ch = max(default_ch_grp.ha_chassis, key=lambda x: x.priority,
                           default=None)

        all_ch = self._sb_idl.get_all_chassis()
        gw_ch = self._sb_idl.get_gateway_chassis_from_cms_options()
        ch_to_del = set(all_ch) - set(gw_ch)

        with self._nb_idl.transaction(check_error=True) as txn:
            for ch in ch_to_del:
                txn.add(self._nb_idl.ha_chassis_group_del_chassis(
                        ovn_const.HA_CHASSIS_GROUP_DEFAULT_NAME, ch,
                        if_exists=True))

            # NOTE(lucasagomes): If the high priority chassis is in
            # the list of chassis to be added/updated. Add it first with
            # the highest priority number possible and then add the rest
            # (the priority of the rest of the chassis does not matter
            # since only the highest one is active)
            priority = ovn_const.HA_CHASSIS_GROUP_HIGHEST_PRIORITY
            if high_prio_ch and high_prio_ch.chassis_name in gw_ch:
                txn.add(self._nb_idl.ha_chassis_group_add_chassis(
                        ovn_const.HA_CHASSIS_GROUP_DEFAULT_NAME,
                        high_prio_ch.chassis_name, priority=priority))
                gw_ch.remove(high_prio_ch.chassis_name)
                priority -= 1

            for ch in gw_ch:
                txn.add(self._nb_idl.ha_chassis_group_add_chassis(
                        ovn_const.HA_CHASSIS_GROUP_DEFAULT_NAME,
                        ch, priority=priority))
                priority -= 1

        raise periodics.NeverAgain()

    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @periodics.periodic(spacing=600, run_immediately=True)
    def check_for_localnet_legacy_port_name(self):
        if not self.has_lock:
            return

        admin_context = n_context.get_admin_context()
        cmds = []
        for ls in self._nb_idl.ls_list().execute(check_error=True):
            network_id = ls.name.replace('neutron-', '')
            legacy_name = utils.ovn_provnet_port_name(network_id)
            legacy_port = None
            segment_id = None
            for lsp in ls.ports:
                if legacy_name == lsp.name:
                    legacy_port = lsp
                    break
            else:
                continue
            for segment in segments_db.get_network_segments(
                    admin_context, network_id):
                if (segment.get(segment_def.PHYSICAL_NETWORK) ==
                        legacy_port.options['network_name']):
                    segment_id = segment['id']
                    break
            if not segment_id:
                continue
            new_p_name = utils.ovn_provnet_port_name(segment_id)
            cmds.append(self._nb_idl.db_set('Logical_Switch_Port',
                                            legacy_port.uuid,
                                            ('name', new_p_name)))
        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)
        raise periodics.NeverAgain()

    # TODO(lucasagomes): Remove this in the Y cycle
    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @periodics.periodic(spacing=600, run_immediately=True)
    def check_for_mcast_flood_reports(self):
        if not self.has_lock:
            return

        cmds = []
        for port in self._nb_idl.lsp_list().execute(check_error=True):
            port_type = port.type.strip()
            if port_type in ("vtep", "localport", "router"):
                continue

            options = port.options
            if ovn_const.LSP_OPTIONS_MCAST_FLOOD_REPORTS in options:
                continue

            options.update({ovn_const.LSP_OPTIONS_MCAST_FLOOD_REPORTS: 'true'})
            if port_type == ovn_const.LSP_TYPE_LOCALNET:
                options.update({ovn_const.LSP_OPTIONS_MCAST_FLOOD: 'false'})

            cmds.append(self._nb_idl.lsp_set_options(port.name, **options))

        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)

        raise periodics.NeverAgain()


class HashRingHealthCheckPeriodics(object):

    def __init__(self, group):
        self._group = group
        self.ctx = n_context.get_admin_context()

    @periodics.periodic(spacing=ovn_const.HASH_RING_TOUCH_INTERVAL)
    def touch_hash_ring_nodes(self):
        # NOTE(lucasagomes): Note that we do not rely on the OVSDB lock
        # here because we want the maintenance tasks from each instance to
        # execute this task.
        hash_ring_db.touch_nodes_from_host(self.ctx, self._group)

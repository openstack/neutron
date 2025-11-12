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
import functools
import inspect
import threading

import futurist
from futurist import periodics
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib import constants as n_const
from neutron_lib import context as n_context
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import l3 as l3_exc
from oslo_config import cfg
from oslo_log import log
from oslo_utils import timeutils
from ovsdbapp.backend.ovs_idl import event as row_event
from ovsdbapp.backend.ovs_idl import rowview

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.conf.agent import ovs_conf
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.db import ovn_hash_ring_db as hash_ring_db
from neutron.db import ovn_revision_numbers_db as revision_numbers_db
from neutron.objects import network as network_obj
from neutron.objects import ports as ports_obj
from neutron.objects import router as router_obj
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.extensions import qos \
    as qos_extension
from neutron import service
from neutron.services.logapi.drivers.ovn import driver as log_driver


CONF = cfg.CONF
LOG = log.getLogger(__name__)

INCONSISTENCY_TYPE_CREATE_UPDATE = 'create/update'
INCONSISTENCY_TYPE_DELETE = 'delete'


def has_lock_periodic(*args, periodic_run_limit=0, **kwargs):
    def wrapper(f):
        _retries = 0

        @functools.wraps(f)
        @periodics.periodic(*args, **kwargs)
        def decorator(self, *args, **kwargs):
            # This periodic task is included in DBInconsistenciesPeriodics
            # since it uses the lock to ensure only one worker is executing
            # additonally, if periodic_run_limit parameter with value > 0 is
            # provided and lock is not acquired for periodic_run_limit
            # times, task will not be run anymore by this maintenance worker
            nonlocal _retries
            if not self.has_lock:
                if periodic_run_limit > 0:
                    if _retries >= periodic_run_limit:
                        LOG.debug("Have not been able to acquire lock to run "
                                  "task '%s' after %s tries, limit reached. "
                                  "No more attempts will be made.",
                                  f, _retries)
                        raise periodics.NeverAgain()
                    _retries += 1
                return
            return f(self, *args, **kwargs)
        return decorator
    return wrapper


class MaintenanceThread:

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
            self._worker = periodics.PeriodicWorker(
                self._callables,
                executor_factory=futurist.ThreadPoolExecutor)
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
        super().__init__(events, table, None)
        self.event_name = self.__class__.__name__

    def run(self, event, row, old):
        curr_version = self.driver.get_ovn_nbdb_version()
        if self.version != curr_version:
            self.driver.nbdb_schema_updated_hook()
            self.version = curr_version


class SchemaAwarePeriodicsBase:

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
        super().__init__(ovn_client)

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
            ovn_const.TYPE_ADDRESS_GROUPS: {
                'neutron_get': self._ovn_client._plugin.get_address_group,
                'ovn_get': self._nb_idl.get_address_set,
                'ovn_create': self._ovn_client.create_address_group,
                'ovn_update': self._ovn_client.update_address_group,
                'ovn_delete': self._ovn_client.delete_address_group,
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
        try:
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
                elif row.resource_type == ovn_const.TYPE_ADDRESS_GROUPS:
                    need_bump = False
                    for obj in ovn_obj:
                        if not obj:
                            # NOTE(liushy): We create two Address_Sets for
                            # one Address_Group at one ovn_create func.
                            res_map['ovn_create'](context, n_obj)
                            need_bump = False
                            break
                        ext_ids = getattr(obj, 'external_ids', {})
                        ovn_revision = int(ext_ids.get(
                            ovn_const.OVN_REV_NUM_EXT_ID_KEY, -1))
                        # NOTE(liushy): We have created two Address_Sets
                        # for one Address_Group, and we update both of
                        # them at one ovn_update func.
                        if ovn_revision != n_obj['revision_number']:
                            res_map['ovn_update'](context, n_obj)
                            need_bump = False
                            break
                        need_bump = True
                    if need_bump:
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
        except revision_numbers_db.StandardAttributeIDNotFound:
            LOG.error('Standard attribute ID not found for object ID %s',
                      n_obj['id'])

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

            fail_str = ', '.join(f'{k}={v}' for k, v in c.items())
            LOG.debug('Maintenance task: Number of inconsistencies '
                      'found at %(type_)s: %(fail_str)s',
                      {'type_': type_, 'fail_str': fail_str})

        _log(create_update_inconsistencies, INCONSISTENCY_TYPE_CREATE_UPDATE)
        _log(delete_inconsistencies, INCONSISTENCY_TYPE_DELETE)

    @has_lock_periodic(spacing=ovn_const.DB_CONSISTENCY_CHECK_INTERVAL,
                       run_immediately=True)
    def check_for_inconsistencies(self):
        admin_context = n_context.get_admin_context()
        create_update_inconsistencies = (
            revision_numbers_db.get_inconsistent_resources(admin_context))
        delete_inconsistencies = (
            revision_numbers_db.get_deleted_resources(admin_context))
        if not any([create_update_inconsistencies, delete_inconsistencies]):
            LOG.debug('Maintenance task: No inconsistencies found. Skipping')
            return

        LOG.debug('Maintenance task: Synchronizing Neutron '
                  'and OVN databases started')
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
                elif row.resource_type == ovn_const.TYPE_PORTS:
                    self._ovn_client.delete_port(admin_context,
                                                 row.resource_uuid)
                else:
                    self._fix_delete(admin_context, row)
            except Exception:
                LOG.exception('Maintenance task: Failed to fix deleted '
                              'resource %(res_uuid)s (type: %(res_type)s)',
                              {'res_uuid': row.resource_uuid,
                               'res_type': row.resource_type})

        self._sync_timer.stop()
        LOG.info('Maintenance task: Synchronization completed '
                 '(took %.2f seconds)', self._sync_timer.elapsed())

    def _create_lrouter_port(self, context, port):
        router_id = port['device_id']
        iface_info = self._ovn_client._l3_plugin._add_neutron_router_interface(
            context, router_id, {'port_id': port['id']})
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
    @has_lock_periodic(
        periodic_run_limit=ovn_const.MAINTENANCE_TASK_RETRY_LIMIT,
        spacing=ovn_const.MAINTENANCE_ONE_RUN_TASK_SPACING,
        run_immediately=True)
    def update_lrouter_ports_ext_ids_name_prefix(self):
        """Update OVN logical router ports if missing external ids
        "neutron-" prefix for router name.
        """
        LOG.debug(
            'Maintenance task: Check missing prefix router_name in '
            'external_ids of LRPs.')
        self._sync_timer.restart()
        ports_to_prefix = []
        rports = self._nb_idl.db_find(
            'Logical_Router_Port').execute(check_error=True)
        for port in rports:
            ext_id_rname = port['external_ids'].get(
                ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY)
            if ext_id_rname and not ext_id_rname.startswith(
                    ovn_const.OVN_NAME_PREFIX):
                ports_to_prefix.append(port)
        if ports_to_prefix:
            LOG.debug('Update missing prefix for router_name in %d LRPs:\n%s',
                      len(ports_to_prefix),
                      [str(p['_uuid']) for p in ports_to_prefix])
            with self._nb_idl.transaction(check_error=True) as txn:
                for port in ports_to_prefix:
                    router_id = port['external_ids'].get(
                        ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY)
                    txn.add(self._nb_idl.update_lrouter_port(
                        name=port.name,
                        external_ids=self._ovn_client._gen_router_port_ext_ids(
                            port, router_id)))
        self._sync_timer.stop()
        LOG.info('Maintenance task: Check missing prefix router_name in LRPs '
                 '(took %.2f seconds)', self._sync_timer.elapsed())
        raise periodics.NeverAgain()

    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @has_lock_periodic(
        periodic_run_limit=ovn_const.MAINTENANCE_TASK_RETRY_LIMIT,
        spacing=ovn_const.MAINTENANCE_ONE_RUN_TASK_SPACING,
        run_immediately=True)
    def check_global_dhcp_opts(self):
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
        LOG.info('Maintenance task: DHCP options check completed '
                 '(took %.2f seconds)', self._sync_timer.elapsed())

        raise periodics.NeverAgain()

    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @has_lock_periodic(
        periodic_run_limit=ovn_const.MAINTENANCE_TASK_RETRY_LIMIT,
        spacing=ovn_const.MAINTENANCE_ONE_RUN_TASK_SPACING,
        run_immediately=True)
    def check_for_igmp_snoop_support(self):
        snooping_conf = ovs_conf.get_igmp_snooping_enabled()
        flood_conf = ovs_conf.get_igmp_flood_unregistered()

        cmds = []
        for ls in self._nb_idl.ls_list().execute(check_error=True):
            if ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY not in ls.external_ids:
                continue
            snooping = ls.other_config.get(ovn_const.MCAST_SNOOP)
            flood = ls.other_config.get(ovn_const.MCAST_FLOOD_UNREGISTERED)

            if (not ls.name or (snooping == snooping_conf and
                                flood == flood_conf)):
                continue

            cmds.append(self._nb_idl.db_set(
                    'Logical_Switch', ls.name,
                    ('other_config', {
                        ovn_const.MCAST_SNOOP: snooping_conf,
                        ovn_const.MCAST_FLOOD_UNREGISTERED: flood_conf})))

        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)

        raise periodics.NeverAgain()

    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @has_lock_periodic(
        periodic_run_limit=ovn_const.MAINTENANCE_TASK_RETRY_LIMIT,
        spacing=ovn_const.MAINTENANCE_ONE_RUN_TASK_SPACING,
        run_immediately=True)
    def check_localnet_port_has_learn_fdb(self):
        ports = self._nb_idl.db_find_rows(
            "Logical_Switch_Port", ("type", "=", ovn_const.LSP_TYPE_LOCALNET)
        ).execute(check_error=True)

        with self._nb_idl.transaction(check_error=True) as txn:
            for port in ports:
                if ovn_conf.is_learn_fdb_enabled():
                    fdb_opt = port.options.get(
                        ovn_const.LSP_OPTIONS_LOCALNET_LEARN_FDB)
                    if not fdb_opt or fdb_opt == 'false':
                        txn.add(self._nb_idl.db_set(
                            'Logical_Switch_Port', port.name,
                            ('options',
                             {ovn_const.LSP_OPTIONS_LOCALNET_LEARN_FDB: 'true'}
                             )))
                elif port.options.get(
                        ovn_const.LSP_OPTIONS_LOCALNET_LEARN_FDB) == 'true':
                    txn.add(self._nb_idl.db_set(
                        'Logical_Switch_Port', port.name,
                        ('options',
                         {ovn_const.LSP_OPTIONS_LOCALNET_LEARN_FDB: 'false'})))
        raise periodics.NeverAgain()

    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @has_lock_periodic(
        periodic_run_limit=ovn_const.MAINTENANCE_TASK_RETRY_LIMIT,
        spacing=ovn_const.MAINTENANCE_ONE_RUN_TASK_SPACING,
        run_immediately=True)
    def check_redirect_type_router_gateway_ports(self):
        """Check OVN router gateway ports
        Check for the option "redirect-type=bridged" value for
        router gateway ports.
        """
        context = n_context.get_admin_context()
        cmds = []
        gw_ports = self._ovn_client._plugin.get_ports(
            context, {'device_owner': [n_const.DEVICE_OWNER_ROUTER_GW]})
        for gw_port in gw_ports:
            router = self._ovn_client._l3_plugin.get_router(
                context, gw_port['device_id'])
            if not utils.is_ovn_provider_router(router):
                continue
            enable_redirect = False
            if ovn_conf.is_ovn_distributed_floating_ip():
                try:
                    r_ports = self._ovn_client._get_router_ports(
                        context, gw_port['device_id'])
                except l3_exc.RouterNotFound:
                    LOG.debug("No Router %s not found", gw_port['device_id'])
                    continue
                else:
                    network_ids = {port['network_id'] for port in r_ports}
                    networks = self._ovn_client._plugin.get_networks(
                        context, filters={'id': network_ids})
                    # NOTE(ltomasbo): For VLAN type networks connected through
                    # the gateway port there is a need to set the redirect-type
                    # option to bridge to ensure traffic is not centralized
                    # through the controller.
                    # If there are no VLAN type networks attached we need to
                    # still make it centralized.
                    if networks:
                        enable_redirect = all(
                            net.get(pnet.NETWORK_TYPE) in [n_const.TYPE_VLAN,
                                                           n_const.TYPE_FLAT]
                            for net in networks)

            lrp_name = utils.ovn_lrouter_port_name(gw_port['id'])
            lrp = self._nb_idl.get_lrouter_port(lrp_name)
            redirect_value = lrp.options.get(
                ovn_const.LRP_OPTIONS_REDIRECT_TYPE)
            if enable_redirect:
                if redirect_value != ovn_const.BRIDGE_REDIRECT_TYPE:
                    opt = {ovn_const.LRP_OPTIONS_REDIRECT_TYPE:
                           ovn_const.BRIDGE_REDIRECT_TYPE}
                    cmds.append(self._nb_idl.db_set(
                        'Logical_Router_Port', lrp_name, ('options', opt)))
            else:
                if redirect_value == ovn_const.BRIDGE_REDIRECT_TYPE:
                    cmds.append(self._nb_idl.db_remove(
                        'Logical_Router_Port', lrp_name, 'options',
                        (ovn_const.LRP_OPTIONS_REDIRECT_TYPE)))
        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)
        raise periodics.NeverAgain()

    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @has_lock_periodic(
        periodic_run_limit=ovn_const.MAINTENANCE_TASK_RETRY_LIMIT,
        spacing=ovn_const.MAINTENANCE_ONE_RUN_TASK_SPACING,
        run_immediately=True)
    def check_provider_distributed_ports(self):
        """Check provider (VLAN and FLAT) distributed ports
        Check for the option "reside-on-redirect-chassis" value for
        distributed ports which belongs to the FLAT or VLAN networks.
        """
        context = n_context.get_admin_context()
        cmds = []
        # Get router ports belonging to VLAN or FLAT networks
        vlan_nets = self._ovn_client._plugin.get_networks(
            context, {pnet.NETWORK_TYPE: [n_const.TYPE_VLAN,
                                          n_const.TYPE_FLAT]})
        vlan_net_ids = [vn['id'] for vn in vlan_nets]
        router_ports = self._ovn_client._plugin.get_ports(
            context, {'network_id': vlan_net_ids,
                      'device_owner': n_const.ROUTER_PORT_OWNERS})

        for rp in router_ports:
            expected_value = (
                self._ovn_client._get_reside_redir_for_gateway_port(
                    context, rp['device_id']))
            lrp_name = utils.ovn_lrouter_port_name(rp['id'])
            lrp = self._nb_idl.get_lrouter_port(lrp_name)
            if lrp and lrp.options.get(
                    ovn_const.LRP_OPTIONS_RESIDE_REDIR_CH) != expected_value:
                opt = {ovn_const.LRP_OPTIONS_RESIDE_REDIR_CH: expected_value}
                cmds.append(self._nb_idl.db_set(
                    'Logical_Router_Port', lrp_name, ('options', opt)))
        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)
        raise periodics.NeverAgain()

    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @has_lock_periodic(
        periodic_run_limit=ovn_const.MAINTENANCE_TASK_RETRY_LIMIT,
        spacing=ovn_const.MAINTENANCE_ONE_RUN_TASK_SPACING,
        run_immediately=True)
    def check_fdb_aging_settings(self):
        """Check FDB aging settings

        Ensure FDB aging settings are enforced. This method should NOT be
        removed. It will be executed anytime the maintenance task is restarted.
        If the ``fdb_age_threshold`` configuration parameter changes, this
        method will update the ``Logical_Switch`` configuration.
        """
        context = n_context.get_admin_context()
        cmds = [self._nb_idl.set_nb_global_options(
            fdb_removal_limit=ovn_conf.get_fdb_removal_limit())]

        config_fdb_age_threshold = ovn_conf.get_fdb_age_threshold()
        # Get provider networks
        nets = self._ovn_client._plugin.get_networks(context)
        for net in nets:
            if not utils.is_provider_network(net):
                continue
            ls_name = utils.ovn_name(net['id'])
            ls = self._nb_idl.get_lswitch(ls_name)
            ls_fdb_age_threshold = ls.other_config.get(
                ovn_const.LS_OPTIONS_FDB_AGE_THRESHOLD)

            if config_fdb_age_threshold != ls_fdb_age_threshold:
                other_config = {ovn_const.LS_OPTIONS_FDB_AGE_THRESHOLD:
                                config_fdb_age_threshold}
                cmds.append(self._nb_idl.db_set(
                    'Logical_Switch', ls_name,
                    ('other_config', other_config)))
        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)
        raise periodics.NeverAgain()

    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @has_lock_periodic(
        periodic_run_limit=ovn_const.MAINTENANCE_TASK_RETRY_LIMIT,
        spacing=ovn_const.MAINTENANCE_ONE_RUN_TASK_SPACING,
        run_immediately=True)
    def update_mac_aging_settings(self):
        """Ensure that MAC_Binding aging options are set"""
        removal_limit = ovn_conf.get_ovn_mac_binding_removal_limit()
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.set_nb_global_options(
                mac_binding_removal_limit=removal_limit))
            txn.add(self._nb_idl.set_router_mac_age_limit())
        raise periodics.NeverAgain()

    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @has_lock_periodic(
        periodic_run_limit=ovn_const.MAINTENANCE_TASK_RETRY_LIMIT,
        spacing=ovn_const.MAINTENANCE_ONE_RUN_TASK_SPACING,
        run_immediately=True)
    def check_baremetal_ports_dhcp_options(self):
        """Update baremetal ports DHCP options

        Update baremetal ports DHCP options based on the
        "disable_ovn_dhcp_for_baremetal_ports" configuration option.
        """
        context = n_context.get_admin_context()
        ports = ports_obj.Port.get_ports_by_vnic_type_and_host(
            context, portbindings.VNIC_BAREMETAL)
        ports = self._ovn_client._plugin.get_ports(
            context, filters={'id': [p.id for p in ports]})
        if not ports:
            raise periodics.NeverAgain()

        with self._nb_idl.transaction(check_error=True) as txn:
            for port in ports:
                lsp = self._nb_idl.lsp_get(port['id']).execute(
                    check_error=True)
                if not lsp:
                    continue

                update_dhcp = False
                if ovn_conf.is_ovn_dhcp_disabled_for_baremetal():
                    if lsp.dhcpv4_options or lsp.dhcpv6_options:
                        update_dhcp = True
                else:
                    if not lsp.dhcpv4_options and not lsp.dhcpv6_options:
                        update_dhcp = True

                if update_dhcp:
                    port_info = self._ovn_client._get_port_options(
                        context, port)
                    dhcpv4_options, dhcpv6_options = (
                        self._ovn_client.update_port_dhcp_options(
                            port_info, txn))
                    txn.add(self._nb_idl.set_lswitch_port(
                        lport_name=port['id'],
                        dhcpv4_options=dhcpv4_options,
                        dhcpv6_options=dhcpv6_options,
                        if_exists=False))

        raise periodics.NeverAgain()

    @has_lock_periodic(
        periodic_run_limit=ovn_const.MAINTENANCE_TASK_RETRY_LIMIT,
        spacing=ovn_const.MAINTENANCE_ONE_RUN_TASK_SPACING,
        run_immediately=True)
    def check_router_default_route_empty_dst_ip(self):
        """Check routers with default route with empty dst-ip (LP: #2002993).
        """
        cmds = []
        for router in self._nb_idl.lr_list().execute(check_error=True):
            if not router.external_ids.get(ovn_const.OVN_REV_NUM_EXT_ID_KEY):
                continue
            routes_to_delete = [
                (r.ip_prefix, '')
                for r in self._nb_idl.lr_route_list(router.uuid).execute(
                    check_error=True)
                if r.nexthop == '' and r.ip_prefix in (n_const.IPv4_ANY,
                                                       n_const.IPv6_ANY)
            ]
            cmds.append(
                self._nb_idl.delete_static_routes(router.name,
                                                  routes_to_delete))

        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)

        raise periodics.NeverAgain()

    @has_lock_periodic(
        periodic_run_limit=ovn_const.MAINTENANCE_TASK_RETRY_LIMIT,
        spacing=ovn_const.MAINTENANCE_ONE_RUN_TASK_SPACING,
        run_immediately=True)
    def check_fair_meter_consistency(self):
        """Update the logging meter after neutron-server reload

        When we change the rate and burst limit we need to update the fair
        meter band to apply the new values. This is called from the ML2/OVN
        driver after the OVN NB idl is loaded

        """
        if log_driver.OVNDriver.network_logging_supported(self._nb_idl):
            meter_name = (
                cfg.CONF.network_log.local_output_log_base or "acl_log_meter")
            self._ovn_client.create_ovn_fair_meter(meter_name,
                                                   from_reload=True)
        raise periodics.NeverAgain()

    @has_lock_periodic(spacing=86400, run_immediately=True)
    def cleanup_old_hash_ring_nodes(self):
        """Daily task to cleanup old stable Hash Ring node entries.

        Runs once a day and clean up Hash Ring entries that haven't
        been updated in more than 5 days. See LP #2033281 for more
        information.

        """
        context = n_context.get_admin_context()
        hash_ring_db.cleanup_old_nodes(context, days=5)

    @has_lock_periodic(spacing=86400, run_immediately=True)
    def configure_nb_global(self):
        """Configure Northbound OVN NB_Global options

        The method goes over all config options from ovn_nb_global config
        sections and configures same key/value pairs to the NB_Global:options
        column.
        """
        options = {opt.name: str(cfg.CONF.ovn_nb_global.get(opt.name)).lower()
                   for opt in ovn_conf.nb_global_opts}

        self._nb_idl.set_nb_global_options(**options).execute(
            check_error=True)

        raise periodics.NeverAgain()

    @has_lock_periodic(spacing=86400, run_immediately=True)
    def update_router_distributed_flag(self):
        """Set "enable_distributed_floating_ip" on the router.distributed flag.

        This method is needed to sync the static configuration parameter
        "enable_distributed_floating_ip", loaded when the Neutron API starts,
        and the router.distributed flag.

        NOTE: remove this method when the RFE that allows to define the
        distributed flag per FIP is implemented. At this point, the
        router.distributed flag will be useless.
            RFE: https://bugs.launchpad.net/neutron/+bug/1978039
        """
        distributed = ovn_conf.is_ovn_distributed_floating_ip()
        router_obj.RouterExtraAttributes.update_distributed_flag(
            n_context.get_admin_context(), distributed)

        raise periodics.NeverAgain()

    @has_lock_periodic(
        periodic_run_limit=ovn_const.MAINTENANCE_TASK_RETRY_LIMIT,
        spacing=ovn_const.MAINTENANCE_ONE_RUN_TASK_SPACING,
        run_immediately=True)
    def update_nat_floating_ip_with_gateway_port_reference(self):
        """Set NAT rule gateway_port column to any floating IP without
        router gateway port uuid reference - LP#2035281.
        """

        if not utils.is_nat_gateway_port_supported(self._nb_idl):
            raise periodics.NeverAgain()

        context = n_context.get_admin_context()
        fip_update = []
        lrouters = self._nb_idl.get_all_logical_routers_with_rports()
        for router in lrouters:
            ovn_fips = router['dnat_and_snats']
            for ovn_fip in ovn_fips:
                # Skip FIPs that are already configured with gateway_port
                if ovn_fip['gateway_port']:
                    continue
                fip_id = ovn_fip['external_ids'].get(
                            ovn_const.OVN_FIP_EXT_ID_KEY)
                if fip_id:
                    fip_update.append({'uuid': ovn_fip['uuid'],
                                       'router_id': router['name']})

        # Simple caching mechanism to avoid unnecessary DB calls
        gw_port_id_cache = {}
        lrp_cache = {}
        cmds = []
        for fip in fip_update:
            lrouter = utils.ovn_name(fip['router_id'])
            if lrouter not in gw_port_id_cache.keys():
                router_db = self._ovn_client._l3_plugin.get_router(
                    context, fip['router_id'], fields=['gw_port_id'])
                gw_port_id_cache[lrouter] = router_db.get('gw_port_id')
                lrp_cache[lrouter] = self._nb_idl.get_lrouter_port(
                    gw_port_id_cache[lrouter])
            columns = {'gateway_port': lrp_cache[lrouter].uuid}
            cmds.append(self._nb_idl.set_nat_rule_in_lrouter(
                lrouter, fip['uuid'], **columns))

        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)
        raise periodics.NeverAgain()

    # TODO(ralonsoh): Remove this method in the G+4 cycle (SLURP release)
    @has_lock_periodic(
        periodic_run_limit=ovn_const.MAINTENANCE_TASK_RETRY_LIMIT,
        spacing=ovn_const.MAINTENANCE_ONE_RUN_TASK_SPACING,
        run_immediately=True)
    def set_network_type_and_physnet(self):
        """Add the network type and physnet to the Logical_Switch registers"""
        context = n_context.get_admin_context()
        net_segments = network_obj.NetworkSegment.get_objects(context)
        net_type = {seg.network_id: seg.network_type for seg in net_segments}
        net_physnet = {seg.network_id: seg.physical_network
                       for seg in net_segments}
        cmds = []
        for ls in self._nb_idl.ls_list().execute(check_error=True):
            if ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY not in ls.external_ids:
                continue

            net_id = utils.get_neutron_name(ls.name)
            physnet = net_physnet[net_id]
            if (ovn_const.OVN_NETTYPE_EXT_ID_KEY not in ls.external_ids or
                    (ovn_const.OVN_PHYSNET_EXT_ID_KEY not in ls.external_ids
                     and physnet)):
                external_ids = {
                    ovn_const.OVN_NETTYPE_EXT_ID_KEY: net_type[net_id]}
                if physnet:
                    external_ids[ovn_const.OVN_PHYSNET_EXT_ID_KEY] = physnet
                cmds.append(self._nb_idl.db_set(
                    'Logical_Switch', ls.uuid, ('external_ids', external_ids)))

        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)

        raise periodics.NeverAgain()

    @has_lock_periodic(
        periodic_run_limit=ovn_const.MAINTENANCE_TASK_RETRY_LIMIT,
        spacing=ovn_const.MAINTENANCE_ONE_RUN_TASK_SPACING,
        run_immediately=True)
    def check_network_broadcast_arps_to_all_routers(self):
        """Check the broadcast-arps-to-all-routers config

        Ensure that the broadcast-arps-to-all-routers is set accordingly
        to the ML2/OVN configuration option.
        """
        context = n_context.get_admin_context()
        networks = self._ovn_client._plugin.get_networks(
            context, filters={external_net.EXTERNAL: [True]})
        cmds = []
        for net in networks:
            ls_name = utils.ovn_name(net['id'])
            ls = self._nb_idl.get_lswitch(ls_name)
            broadcast_value = ls.other_config.get(
                ovn_const.LS_OPTIONS_BROADCAST_ARPS_ROUTERS)
            expected_broadcast_value = (
                'true'
                if ovn_conf.is_broadcast_arps_to_all_routers_enabled() else
                'false')
            # Assert the config value is the right one
            if broadcast_value == expected_broadcast_value:
                continue
            # If not, set the right value
            other_config = {ovn_const.LS_OPTIONS_BROADCAST_ARPS_ROUTERS:
                            expected_broadcast_value}
            cmds.append(self._nb_idl.db_set('Logical_Switch', ls_name,
                                            ('other_config', other_config)))
        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)
        raise periodics.NeverAgain()

    # TODO(racosta): Remove this method in the E+2 cycle (SLURP release)
    @has_lock_periodic(spacing=600, run_immediately=True)
    def update_router_static_routes(self):
        """Set external_ids column to any Neutron's owned static route.
        """

        context = n_context.get_admin_context()
        sroute_update = []
        lrouters = self._nb_idl.get_all_logical_routers_static_routes()
        for router in lrouters:
            sroutes = router['static_routes']
            for sroute in sroutes:
                # Skip Static Routes that are already configured with an
                # external_id key
                if (ovn_const.OVN_LRSR_EXT_ID_KEY not in
                        sroute.external_ids.keys()):
                    sroute_update.append({'sroute': sroute,
                                          'name': router['name']})

        routes_cache = {}
        cmds = []
        columns = {'external_ids': {ovn_const.OVN_LRSR_EXT_ID_KEY: 'true'}}
        for sroute in sroute_update:
            lrouter = utils.ovn_name(sroute['name'])
            if lrouter not in routes_cache.keys():
                router_db = self._ovn_client._l3_plugin.get_router(
                    context, sroute['name'], fields=['routes'])
                routes_cache[lrouter] = router_db.get('routes')

            ovn_route = sroute['sroute']
            for db_route in routes_cache[lrouter]:
                if (ovn_route.ip_prefix == db_route['destination'] and
                        ovn_route.nexthop == db_route['nexthop']):
                    cmds.append(self._nb_idl.set_static_route(sroute['sroute'],
                                                              **columns))
                    break

        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)
        raise periodics.NeverAgain()

    @has_lock_periodic(
        periodic_run_limit=ovn_const.MAINTENANCE_TASK_RETRY_LIMIT,
        spacing=ovn_const.MAINTENANCE_ONE_RUN_TASK_SPACING,
        run_immediately=True)
    def set_fip_distributed_flag(self):
        """Set the NB_Global.external_ids:fip-distributed flag.

        This method should NOT be removed. It will be executed anytime the
        maintenance task is restarted. If the
        ``enable_distributed_floating_ip`` configuration parameter changes,
        this method will update the ``NB_Global`` register.
        """
        distributed = ovn_conf.is_ovn_distributed_floating_ip()
        LOG.debug(
            "Setting fip-distributed flag in NB_Global to %s", distributed)
        self._nb_idl.db_set(
            'NB_Global', '.', external_ids={
                ovn_const.OVN_FIP_DISTRIBUTED_KEY: str(distributed)}).execute(
                    check_error=True)
        raise periodics.NeverAgain()

    @has_lock_periodic(
        periodic_run_limit=ovn_const.MAINTENANCE_TASK_RETRY_LIMIT,
        spacing=ovn_const.MAINTENANCE_ONE_RUN_TASK_SPACING,
        run_immediately=True)
    def set_ovn_owned_dns_option(self):
        """Set the ovn_owned option as configured for the DNS records"""
        cmds = []
        ovn_owned = ('true' if ovn_conf.is_dns_records_ovn_owned()
                     else 'false')
        dns_options = {ovn_const.OVN_OWNED: ovn_owned}
        for dns in self._nb_idl.dns_list().execute(check_error=True):
            if ('ls_name' in dns.external_ids and
                    dns.options.get(ovn_const.OVN_OWNED) != ovn_owned):
                cmds.append(self._nb_idl.dns_set_options(
                    dns.uuid, **dns_options))

        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)

        raise periodics.NeverAgain()

    # TODO(ralonsoh): to remove in E+4 cycle (2nd next SLURP release)
    @has_lock_periodic(
        periodic_run_limit=ovn_const.MAINTENANCE_TASK_RETRY_LIMIT,
        spacing=ovn_const.MAINTENANCE_ONE_RUN_TASK_SPACING,
        run_immediately=True)
    def update_qos_fip_rule_priority(self):
        """The new QoS FIP rule priority is OVN_QOS_FIP_RULE_PRIORITY"""
        cmds = []
        table = self._nb_idl.tables['QoS']
        for qos_rule in table.rows.values():
            qos_rule = rowview.RowView(qos_rule)
            if qos_rule.external_ids.get(ovn_const.OVN_FIP_EXT_ID_KEY):
                cmds.append(self._nb_idl.db_set(
                    'QoS', qos_rule.uuid,
                    ('priority', qos_extension.OVN_QOS_FIP_RULE_PRIORITY)))

        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)

        raise periodics.NeverAgain()


class HashRingHealthCheckPeriodics:

    def __init__(self, group, node_uuid):
        self._group = group
        self._node_uuid = node_uuid
        self.ctx = n_context.get_admin_context()

    @periodics.periodic(spacing=ovn_const.HASH_RING_TOUCH_INTERVAL)
    def touch_hash_ring_node(self):
        # NOTE(lucasagomes): Note that we do not rely on the OVSDB lock
        # here because we want the maintenance tasks from each instance to
        # execute this task.
        LOG.debug(
            'Touching Hash Ring node "%s" from periodic health check thread',
            self._node_uuid)
        hash_ring_db.touch_node(self.ctx, self._node_uuid)

        # Check the number of the nodes in the ring and log a message in
        # case they are out of sync. See LP #2024205 for more information
        # on this issue.
        api_workers = service._get_api_workers()
        num_nodes = hash_ring_db.count_nodes_from_host(self.ctx, self._group)

        if num_nodes > api_workers:
            LOG.critical(
                'The number of nodes in the Hash Ring (%d) is higher than '
                'the number of API workers (%d) for host "%s". Something is '
                'not right and OVSDB events could be missed because of this. '
                'Please check the status of the Neutron processes, this can '
                'happen when the API workers are killed and restarted. '
                'Restarting the service should fix the issue, see LP '
                '#2024205 for more information.',
                num_nodes, api_workers, cfg.CONF.host)

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
import copy
import inspect
import re
import threading

from futurist import periodics
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib import constants as n_const
from neutron_lib import context as n_context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import timeutils
from ovsdbapp.backend.ovs_idl import event as row_event

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.db import l3_attrs_db
from neutron.db import ovn_hash_ring_db as hash_ring_db
from neutron.db import ovn_revision_numbers_db as revision_numbers_db
from neutron.objects import ports as ports_obj
from neutron.objects import router as router_obj
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_db_sync


CONF = cfg.CONF
LOG = log.getLogger(__name__)

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

    # The migration will run just once per neutron-server instance. If the lock
    # is held by some other neutron-server instance in the cloud, we'll attempt
    # to perform the migration every 10 seconds until completed.
    # TODO(ihrachys): Remove the migration to stateful fips in Z+1.
    @periodics.periodic(spacing=10, run_immediately=True)
    @rerun_on_schema_updates
    def migrate_to_stateful_fips(self):
        """Perform the migration from stateless to stateful Floating IPs. """
        # Only the worker holding a valid lock within OVSDB will perform the
        # migration.
        if not self.has_lock:
            return

        admin_context = n_context.get_admin_context()
        nb_sync = ovn_db_sync.OvnNbSynchronizer(
            self._ovn_client._plugin, self._nb_idl, self._ovn_client._sb_idl,
            None, None)
        nb_sync.migrate_to_stateful_fips(admin_context)
        raise periodics.NeverAgain()

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

    @periodics.periodic(spacing=ovn_const.DB_CONSISTENCY_CHECK_INTERVAL,
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
    @periodics.periodic(spacing=600, run_immediately=True)
    def check_for_igmp_snoop_support(self):
        if not self.has_lock:
            return

        with self._nb_idl.transaction(check_error=True) as txn:
            value = ('true' if ovn_conf.is_igmp_snooping_enabled()
                     else 'false')
            for ls in self._nb_idl.ls_list().execute(check_error=True):
                if (ls.other_config.get(ovn_const.MCAST_SNOOP,
                                        None) == value or not ls.name):
                    continue
                txn.add(self._nb_idl.db_set(
                    'Logical_Switch', ls.name,
                    ('other_config', {
                        ovn_const.MCAST_SNOOP: value,
                        ovn_const.MCAST_FLOOD_UNREGISTERED: 'false'})))

        raise periodics.NeverAgain()

    # TODO(czesla): Remove this in the A+4 cycle
    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @periodics.periodic(spacing=600, run_immediately=True)
    def check_port_has_address_scope(self):
        if not self.has_lock:
            return

        ports = self._nb_idl.db_find_rows(
            "Logical_Switch_Port", ("type", "!=", ovn_const.LSP_TYPE_LOCALNET)
        ).execute(check_error=True)

        context = n_context.get_admin_context()
        with self._nb_idl.transaction(check_error=True) as txn:
            for port in ports:
                if (port.external_ids.get(
                        ovn_const.OVN_SUBNET_POOL_EXT_ADDR_SCOPE4_KEY)
                        is None or
                        port.external_ids.get(
                            ovn_const.OVN_SUBNET_POOL_EXT_ADDR_SCOPE6_KEY)
                        is None):
                    try:
                        port_neutron = self._ovn_client._plugin.get_port(
                            context, port.name
                        )

                        port_info, external_ids = (
                            self._ovn_client.get_external_ids_from_port(
                                port_neutron)
                        )
                        txn.add(self._nb_idl.set_lswitch_port(
                            port.name, external_ids=external_ids))
                    except n_exc.PortNotFound:
                        # The sync function will fix this port
                        pass
                    except Exception:
                        LOG.exception('Failed to update port %s', port.name)
        raise periodics.NeverAgain()

    def _delete_default_ha_chassis_group(self, txn):
        # TODO(lucasgomes): Remove the deletion of the
        # HA_CHASSIS_GROUP_DEFAULT_NAME in the Y cycle. We no longer
        # have a default HA Chassis Group.
        cmd = [self._nb_idl.ha_chassis_group_del(
            ovn_const.HA_CHASSIS_GROUP_DEFAULT_NAME, if_exists=True)]
        self._ovn_client._transaction(cmd, txn=txn)

    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @periodics.periodic(spacing=600, run_immediately=True)
    def check_for_ha_chassis_group(self):
        # If external ports is not supported stop running
        # this periodic task
        if not self._ovn_client.is_external_ports_supported():
            raise periodics.NeverAgain()

        if not self.has_lock:
            return

        external_ports = self._nb_idl.db_find_rows(
            'Logical_Switch_Port', ('type', '=', ovn_const.LSP_TYPE_EXTERNAL)
        ).execute(check_error=True)

        context = n_context.get_admin_context()
        with self._nb_idl.transaction(check_error=True) as txn:
            for port in external_ports:
                network_id = port.external_ids[
                    ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY].replace(
                        ovn_const.OVN_NAME_PREFIX, '')
                ha_ch_grp = self._ovn_client.sync_ha_chassis_group(
                    context, network_id, txn)
                try:
                    port_ha_ch_uuid = port.ha_chassis_group[0].uuid
                except IndexError:
                    port_ha_ch_uuid = None
                if port_ha_ch_uuid != ha_ch_grp:
                    txn.add(self._nb_idl.set_lswitch_port(
                        port.name, ha_chassis_group=ha_ch_grp))

            self._delete_default_ha_chassis_group(txn)

        raise periodics.NeverAgain()

    # TODO(lucasagomes): Remove this in the Z cycle
    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @periodics.periodic(spacing=600, run_immediately=True)
    def check_for_mcast_flood_reports(self):
        if not self.has_lock:
            return

        cmds = []
        for port in self._nb_idl.lsp_list().execute(check_error=True):
            port_type = port.type.strip()
            if port_type in ("vtep", ovn_const.LSP_TYPE_LOCALPORT, "router"):
                continue

            options = port.options
            if port_type == ovn_const.LSP_TYPE_LOCALNET:
                mcast_flood_value = options.get(
                    ovn_const.LSP_OPTIONS_MCAST_FLOOD_REPORTS)
                if mcast_flood_value == 'false':
                    continue
                options.update({ovn_const.LSP_OPTIONS_MCAST_FLOOD: 'false'})
            elif ovn_const.LSP_OPTIONS_MCAST_FLOOD_REPORTS in options:
                continue

            options.update({ovn_const.LSP_OPTIONS_MCAST_FLOOD_REPORTS: 'true'})
            cmds.append(self._nb_idl.lsp_set_options(port.name, **options))

        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)

        raise periodics.NeverAgain()

    # TODO(lucasagomes): Remove this in the Z cycle
    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @periodics.periodic(spacing=600, run_immediately=True)
    def check_router_mac_binding_options(self):
        if not self.has_lock:
            return

        cmds = []
        for router in self._nb_idl.lr_list().execute(check_error=True):
            if (router.options.get('always_learn_from_arp_request') and
                    router.options.get('dynamic_neigh_routers')):
                continue

            opts = copy.deepcopy(router.options)
            opts.update({'always_learn_from_arp_request': 'false',
                         'dynamic_neigh_routers': 'true'})
            cmds.append(self._nb_idl.update_lrouter(router.name, options=opts))

        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)
        raise periodics.NeverAgain()

    # TODO(ralonsoh): Remove this in the Z+2 cycle
    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @periodics.periodic(spacing=600, run_immediately=True)
    def update_port_qos_with_external_ids_reference(self):
        """Update all OVN QoS registers with the port ID

        This method will only update the OVN QoS registers related to port QoS,
        not FIP QoS. FIP QoS have the corresponding "external_ids" reference.
        """
        if not self.has_lock:
            return

        regex = re.compile(
            r'(inport|outport) == \"(?P<port_id>[a-z0-9\-]{36})\"')
        cmds = []
        for ls in self._nb_idl.ls_list().execute(check_error=True):
            for qos in self._nb_idl.qos_list(ls.name).execute(
                    check_error=True):
                if qos.external_ids:
                    continue
                match = re.match(regex, qos.match)
                if not match:
                    continue
                port_id = match.group('port_id')
                external_ids = {ovn_const.OVN_PORT_EXT_ID_KEY: port_id}
                cmds.append(self._nb_idl.db_set(
                    'QoS', qos.uuid, ('external_ids', external_ids)))

        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)
        raise periodics.NeverAgain()

    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @periodics.periodic(spacing=600, run_immediately=True)
    def check_vlan_distributed_ports(self):
        """Check VLAN distributed ports
        Check for the option "reside-on-redirect-chassis" value for
        distributed VLAN ports.
        """
        if not self.has_lock:
            return
        context = n_context.get_admin_context()
        cmds = []
        # Get router ports belonging to VLAN networks
        vlan_nets = self._ovn_client._plugin.get_networks(
            context, {pnet.NETWORK_TYPE: [n_const.TYPE_VLAN]})
        # FIXME(ltomasbo): Once Bugzilla 2162756 is fixed the
        # is_provider_network check should be removed
        vlan_net_ids = [vn['id'] for vn in vlan_nets
                        if not utils.is_provider_network(vn)]
        router_ports = self._ovn_client._plugin.get_ports(
            context, {'network_id': vlan_net_ids,
                      'device_owner': n_const.ROUTER_PORT_OWNERS})
        expected_value = ('false' if ovn_conf.is_ovn_distributed_floating_ip()
                          else 'true')
        for rp in router_ports:
            lrp_name = utils.ovn_lrouter_port_name(rp['id'])
            lrp = self._nb_idl.get_lrouter_port(lrp_name)
            if lrp.options.get(
                    ovn_const.LRP_OPTIONS_RESIDE_REDIR_CH) != expected_value:
                opt = {ovn_const.LRP_OPTIONS_RESIDE_REDIR_CH: expected_value}
                cmds.append(self._nb_idl.db_set(
                    'Logical_Router_Port', lrp_name, ('options', opt)))
        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)
        raise periodics.NeverAgain()

    # TODO(ralonsoh): Remove this in the Z+3 cycle. This method adds the
    # "external_ids:OVN_GW_NETWORK_EXT_ID_KEY" to each router that has
    # a gateway (that means, that has "external_ids:OVN_GW_PORT_EXT_ID_KEY").
    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @periodics.periodic(spacing=600, run_immediately=True)
    def update_logical_router_with_gateway_network_id(self):
        """Update all OVN logical router registers with the GW network ID"""
        if not self.has_lock:
            return

        cmds = []
        context = n_context.get_admin_context()
        for lr in self._nb_idl.lr_list().execute(check_error=True):
            gw_port = lr.external_ids.get(ovn_const.OVN_GW_PORT_EXT_ID_KEY)
            gw_net = lr.external_ids.get(ovn_const.OVN_GW_NETWORK_EXT_ID_KEY)
            if not gw_port or (gw_port and gw_net):
                # This router does not have a gateway network assigned yet or
                # it has a gateway port and its corresponding network.
                continue

            port = self._ovn_client._plugin.get_port(context, gw_port)
            external_ids = {
                ovn_const.OVN_GW_NETWORK_EXT_ID_KEY: port['network_id']}
            cmds.append(self._nb_idl.db_set(
                'Logical_Router', lr.uuid, ('external_ids', external_ids)))

        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)
        raise periodics.NeverAgain()

    # A static spacing value is used here, but this method will only run
    # once per lock due to the use of periodics.NeverAgain().
    @periodics.periodic(spacing=600, run_immediately=True)
    def check_baremetal_ports_dhcp_options(self):
        """Update baremetal ports DHCP options

        Update baremetal ports DHCP options based on the
        "disable_ovn_dhcp_for_baremetal_ports" configuration option.
        """
        # If external ports is not supported stop running
        # this periodic task
        if not self._ovn_client.is_external_ports_supported():
            raise periodics.NeverAgain()

        if not self.has_lock:
            return

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
                    port_info = self._ovn_client._get_port_options(port)
                    dhcpv4_options, dhcpv6_options = (
                        self._ovn_client.update_port_dhcp_options(
                            port_info, txn))
                    txn.add(self._nb_idl.set_lswitch_port(
                        lport_name=port['id'],
                        dhcpv4_options=dhcpv4_options,
                        dhcpv6_options=dhcpv6_options,
                        if_exists=False))

        raise periodics.NeverAgain()

    # TODO(ralonsoh): Remove this in the Z+4 cycle
    @periodics.periodic(spacing=600, run_immediately=True)
    def update_port_virtual_type(self):
        """Set type=virtual to those ports with parents
        Before LP#1973276, any virtual port with "device_owner" defined, lost
        its type=virtual. This task restores the type for those ports updated
        before the fix https://review.opendev.org/c/openstack/neutron/+/841711.
        """
        if not self.has_lock:
            return

        context = n_context.get_admin_context()
        cmds = []
        for lsp in self._nb_idl.lsp_list().execute(check_error=True):
            if lsp.type != '':
                continue

            try:
                port = self._ovn_client._plugin.get_port(context, lsp.name)
            except n_exc.PortNotFound:
                continue

            for ip in port.get('fixed_ips', []):
                if utils.get_virtual_port_parents(
                        self._nb_idl, ip['ip_address'], port['network_id'],
                        port['id']):
                    cmds.append(self._nb_idl.db_set(
                        'Logical_Switch_Port', lsp.uuid,
                        ('type', ovn_const.LSP_TYPE_VIRTUAL)))
                    break

        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)
        raise periodics.NeverAgain()

    # TODO(ralonsoh): Remove this in the Antelope+4 cycle
    @periodics.periodic(spacing=600, run_immediately=True)
    def create_router_extra_attributes_registers(self):
        """Create missing ``RouterExtraAttributes`` registers.

        ML2/OVN L3 plugin does not inherit the ``ExtraAttributesMixin`` class.
        Before LP#1995974, the L3 plugin was not creating a
        ``RouterExtraAttributes`` register per ``Routers`` register. This one
        only execution method finds those ``Routers`` registers without the
        child one and creates one with the default values.
        """
        if not self.has_lock:
            return

        context = n_context.get_admin_context()
        for router_id in router_obj.Router.\
                get_router_ids_without_router_std_attrs(context):
            with db_api.CONTEXT_WRITER.using(context):
                router_db = {'id': router_id}
                l3_attrs_db.ExtraAttributesMixin.add_extra_attr(context,
                                                                router_db)

        raise periodics.NeverAgain()

    @periodics.periodic(spacing=600, run_immediately=True)
    def check_router_default_route_empty_dst_ip(self):
        """Check routers with default route with empty dst-ip (LP: #2002993).
        """
        if not self.has_lock:
            return

        cmds = []
        for router in self._nb_idl.lr_list().execute(check_error=True):
            if not router.external_ids.get(ovn_const.OVN_REV_NUM_EXT_ID_KEY):
                continue
            for route in self._nb_idl.lr_route_list(router.uuid).execute(
                    check_error=True):
                if (route.nexthop == '' and
                        (route.ip_prefix == n_const.IPv4_ANY or
                         route.ip_prefix == n_const.IPv6_ANY)):
                    cmds.append(
                        self._nb_idl.delete_static_route(
                            router.name, route.ip_prefix, ''))

        if cmds:
            with self._nb_idl.transaction(check_error=True) as txn:
                for cmd in cmds:
                    txn.add(cmd)

        raise periodics.NeverAgain()

    # TODO(ralonsoh): Remove this in the Antelope+4 cycle
    @periodics.periodic(spacing=600, run_immediately=True)
    def add_vnic_type_and_pb_capabilities_to_lsp(self):
        """Add the port VNIC type and port binding capabilities to the LSP.

        This is needed to know if a port has hardware offload capabilities.
        This method is only updating those ports with VNIC type direct, in
        order to minimize the load impact of this method when updating the OVN
        database. Within the patch that adds this maintenance method, it has
        been added to the LSP the VNIC type and the port binding capabilities.
        To implement LP#1998608, only direct ports are needed.
        """
        if not self.has_lock:
            return

        port_bindings = ports_obj.PortBinding.get_port_binding_by_vnic_type(
            n_context.get_admin_context(), portbindings.VNIC_DIRECT)
        with self._nb_idl.transaction(check_error=True) as txn:
            for pb in port_bindings:
                try:
                    profile = jsonutils.loads(pb.profile)
                except ValueError:
                    continue

                capabilities = profile.get(ovn_const.PORT_CAP_PARAM, [])
                external_ids = {
                    ovn_const.OVN_PORT_VNIC_TYPE_KEY: portbindings.VNIC_DIRECT,
                    ovn_const.OVN_PORT_BP_CAPABILITIES_KEY:
                        ';'.join(capabilities)
                }
                txn.add(self._nb_idl.set_lswitch_port(
                    lport_name=pb.port_id, if_exists=True,
                    external_ids=external_ids))

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

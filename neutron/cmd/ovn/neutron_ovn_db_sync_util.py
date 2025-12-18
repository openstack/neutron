# Copyright 2016 Red Hat, Inc.
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

import copy

from neutron_lib.agent import topics
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_db import options as db_options
from oslo_log import log as logging
from stevedore import enabled

from neutron.common import config as common_config
from neutron.common.ovn import constants as ovn_const
from neutron.conf.agent import securitygroups_rpc
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.conf.plugins.ml2.drivers.ovn import ovn_db_sync as sync_conf
from neutron import manager
from neutron import opts as neutron_options
from neutron.plugins.ml2.drivers.ovn.mech_driver import mech_driver
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import impl_idl_ovn
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_db_sync
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import worker
from neutron.plugins.ml2 import plugin as ml2_plugin

LOG = logging.getLogger(__name__)


class Ml2Plugin(ml2_plugin.Ml2Plugin):

    def _setup_dhcp(self):
        pass

    def _start_rpc_notifiers(self):
        # Override the notifier so that when calling the ML2 plugin to create
        # resources, it doesn't crash trying to notify subscribers.
        self.notifier = AgentNotifierApi(topics.AGENT)


class OVNMechanismDriver(mech_driver.OVNMechanismDriver):

    def subscribe(self):
        pass

    def post_fork_initialize(self, resource, event, trigger, **kwargs):
        pass

    @property
    def ovn_client(self):
        return self._ovn_client

    def _remove_node_from_hash_ring(self):
        """Don't remove the node from the Hash Ring.

        If this method was not overridden, cleanup would be performed when
        calling the db sync and running neutron server would remove the
        nodes from the Hash Ring.
        """

    # Since we are not using the ovn mechanism driver while syncing,
    # we override the post and pre commit methods so that original ones are
    # not called.
    def create_port_precommit(self, context):
        pass

    def create_port_postcommit(self, context):
        port = context.current
        self.ovn_client.create_port(context.plugin_context, port)

    def update_port_precommit(self, context):
        pass

    def update_port_postcommit(self, context):
        port = context.current
        original_port = context.original
        self.ovn_client.update_port(context.plugin_context, port,
                                    original_port)

    def delete_port_precommit(self, context):
        pass

    def delete_port_postcommit(self, context):
        port = copy.deepcopy(context.current)
        port['network'] = context.network.current
        self.ovn_client.delete_port(context.plugin_context, port['id'])


class AgentNotifierApi:
    """Default Agent Notifier class for ovn-db-sync-util.

    This class implements empty methods so that when creating resources in
    the core plugin, the original ones don't get called and don't interfere
    with the syncing process.
    """
    def __init__(self, topic):
        self.topic = topic
        self.topic_network_delete = topics.get_topic_name(topic,
                                                          topics.NETWORK,
                                                          topics.DELETE)
        self.topic_port_update = topics.get_topic_name(topic,
                                                       topics.PORT,
                                                       topics.UPDATE)
        self.topic_port_delete = topics.get_topic_name(topic,
                                                       topics.PORT,
                                                       topics.DELETE)
        self.topic_network_update = topics.get_topic_name(topic,
                                                          topics.NETWORK,
                                                          topics.UPDATE)

    def network_delete(self, context, network_id):
        pass

    def port_update(self, context, port, network_type, segmentation_id,
                    physical_network):
        pass

    def port_delete(self, context, port_id):
        pass

    def network_update(self, context, network):
        pass

    def security_groups_provider_updated(self, context,
                                         devices_to_update=None):
        pass


def setup_conf():
    conf = cfg.CONF
    common_config.register_common_config_options()
    ovn_conf.register_opts()
    ml2_group, ml2_opts = neutron_options.list_ml2_conf_opts()[0]
    cfg.CONF.register_cli_opts(ml2_opts, ml2_group)
    cfg.CONF.register_cli_opts(securitygroups_rpc.security_group_opts,
                               'SECURITYGROUP')
    ovn_group, ovn_opts = ovn_conf.list_opts()[0]
    cfg.CONF.register_cli_opts(ovn_opts, group=ovn_group)
    db_group, neutron_db_opts = db_options.list_opts()[0]
    cfg.CONF.register_cli_opts(neutron_db_opts, db_group)
    sync_conf.register_ovn_db_sync_cli_opts(cfg.CONF)
    # Override Nova notify configuration LP: #1882020
    cfg.CONF.set_override('notify_nova_on_port_status_changes', False)
    cfg.CONF.set_override('notify_nova_on_port_data_changes', False)
    return conf


def _load_drivers(entry_point, driver_name=None):

    def load_driver(ext):
        if not issubclass(ext.plugin, ovn_db_sync.BaseOvnDbSynchronizer):
            LOG.error("Extension '%s' is not an instance of "
                      "%s and will not be loaded",
                      ext.name, ovn_db_sync.BaseOvnDbSynchronizer)
            return False
        if driver_name is None:
            return True
        return ext.name == driver_name

    return enabled.EnabledExtensionManager(
        entry_point,
        check_func=load_driver,
        invoke_on_load=False)


def load_synchronize_drivers(driver_name=None):
    return _load_drivers('neutron.ovn.db_sync', driver_name)


def load_db_migration_drivers(driver_name=None):
    return _load_drivers('neutron.ovn.db_migration', driver_name)


def configure_mechanism_drivers(conf, mgr):
    required_mechanism_drivers = set()
    for ext in mgr:
        required_mechanism_drivers |= set(
            ext.plugin.get_required_mechanism_drivers())

    conf.set_override(
        'mechanism_drivers', list(required_mechanism_drivers), 'ml2')


def configure_service_plugins(conf, mgr):
    required_plugins = set()
    for ext in mgr:
        required_plugins |= set(ext.plugin.get_required_service_plugins())

    conf.set_override('service_plugins', list(required_plugins))


def configure_ml2_extension_drivers(conf, mgr):
    required_extension_drivers = set()
    for ext in mgr:
        required_extension_drivers |= set(
            ext.plugin.get_required_ml2_extension_drivers())

    extension_drivers = list(
        set(conf.ml2.extension_drivers) | required_extension_drivers)
    conf.set_override('extension_drivers', extension_drivers, 'ml2')


def synchronize_ovn_dbs(mgr, core_plugin, ovn_driver, mode):
    LOG.info('Neutron OVN DBs sync started with mode: %s', mode)
    for sync_driver in mgr:
        LOG.info('Starting synchronize with %s driver',
                 sync_driver.name)
        sync_obj = sync_driver.plugin(core_plugin, ovn_driver, mode)
        sync_obj.do_sync()
        LOG.info('Driver %s sync completed', sync_driver.name)
    LOG.info('Neutron OVN DBs sync completed')


def migrate_neutron_dbs_to_ovn(drv):
    LOG.info("Database migration from OVS to OVN by plugin %s started",
             drv.name)
    # This will call function defined in the ovn.db_migration entry_point,
    # for example for neutron it is migrate_database_to_ovn() function
    drv.plugin()
    LOG.info("Database migration from OVS to OVN by plugin %s completed",
             drv.name)

def main():
    """Main method for syncing neutron networks and ports with ovn nb db.

    This script provides a utility for syncing the OVN Northbound Database
    with the Neutron database.

    This script is used for the migration from ML2/OVS to ML2/OVN.
    """
    conf = setup_conf()

    # if no config file is passed or no configuration options are passed
    # then load configuration from /etc/neutron/neutron.conf
    try:
        conf(project='neutron')
    except TypeError:
        LOG.error('Error parsing the configuration values. Please verify.')
        raise SystemExit(1)

    logging.setup(conf, 'neutron_ovn_db_sync_util', fix_eventlet=False)
    LOG.info('Neutron OVN DB sync started')
    sync_ext_mgr = load_synchronize_drivers(conf.sync_plugin)
    if not sync_ext_mgr.names():
        LOG.error('No OVN DB sync plugin found')
        raise SystemExit(1)

    LOG.info('Loaded sync plugins: %s', ', '.join(sync_ext_mgr.names()))

    mode = ovn_conf.get_ovn_neutron_sync_mode()
    # Migrate mode will run as repair mode in the synchronizer
    migrate = False
    if mode == ovn_const.OVN_DB_SYNC_MODE_MIGRATE:
        mode = ovn_const.OVN_DB_SYNC_MODE_REPAIR
        migrate = True
    if mode not in [ovn_const.OVN_DB_SYNC_MODE_LOG,
                    ovn_const.OVN_DB_SYNC_MODE_REPAIR]:
        LOG.error(
            'Invalid sync mode: ["%s"]. Should be "%s" or "%s"',
            mode,
            ovn_const.OVN_DB_SYNC_MODE_LOG,
            ovn_const.OVN_DB_SYNC_MODE_REPAIR)
        raise SystemExit(1)

    # Validate and modify core plugin and ML2 mechanism drivers for syncing.
    if (conf.core_plugin.endswith('.Ml2Plugin') or
            conf.core_plugin == 'ml2'):
        conf.core_plugin = (
            'neutron.cmd.ovn.neutron_ovn_db_sync_util.Ml2Plugin')
        if not conf.ml2.mechanism_drivers:
            LOG.error('Please use --config-file to specify '
                      'neutron and ml2 configuration file.')
            raise SystemExit(1)
        if 'ovn' not in conf.ml2.mechanism_drivers:
            LOG.error('No "ovn" mechanism driver found: "%s".',
                      conf.ml2.mechanism_drivers)
            raise SystemExit(1)
        configure_mechanism_drivers(conf, sync_ext_mgr)
        configure_service_plugins(conf, sync_ext_mgr)
        configure_ml2_extension_drivers(conf, sync_ext_mgr)

    else:
        LOG.error('Invalid core plugin: ["%s"].', conf.core_plugin)
        raise SystemExit(1)

    mech_worker = worker.MaintenanceWorker
    try:
        ovn_nb_api = impl_idl_ovn.OvsdbNbOvnIdl.from_worker(mech_worker)
    except RuntimeError:
        LOG.error('Invalid --ovn-ovn_nb_connection parameter provided.')
        raise SystemExit(1)

    try:
        ovn_sb_api = impl_idl_ovn.OvsdbSbOvnIdl.from_worker(mech_worker)
    except RuntimeError:
        LOG.error('Invalid --ovn-ovn_sb_connection parameter provided.')
        raise SystemExit(1)

    manager.init()
    core_plugin = directory.get_plugin()
    driver = core_plugin.mechanism_manager.mech_drivers['ovn-sync']
    # The L3 code looks for the OVSDB connection on the 'ovn' driver
    # and will fail with a KeyError if it isn't there
    core_plugin.mechanism_manager.mech_drivers['ovn'] = driver
    ovn_driver = driver.obj
    ovn_driver.nb_ovn = ovn_nb_api
    ovn_driver.sb_ovn = ovn_sb_api
    ovn_driver._post_fork_event.set()

    synchronize_ovn_dbs(
        sync_ext_mgr, core_plugin, ovn_driver, mode
    )

    # TODO(slaweq): add drivers for the ovs2ovn migration
    if migrate:
        LOG.info("Neutron database migration from OVS to OVN started")
        migration_drivers = load_db_migration_drivers(conf.migration_plugin)
        migration_drivers.map(migrate_neutron_dbs_to_ovn)
        LOG.info("Neutron database migration from OVS to OVN completed")

    LOG.info('Neutron OVN DB sync completed')

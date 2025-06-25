# Copyright (c) 2014 OpenStack Foundation.
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

import copy
from datetime import datetime
import errno
import os
import shutil
from unittest import mock
import warnings
import weakref

import fixtures
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log
from oslo_utils import timeutils
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.agent.linux import utils
from neutron.api import extensions as exts
from neutron.common import utils as n_utils
from neutron.conf.agent import common as config
from neutron.conf.agent import ovs_conf
from neutron.conf.plugins.ml2 import config as ml2_config
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
# Load all the models to register them into SQLAlchemy metadata before using
# the SqlFixture
from neutron.db import models  # noqa
from neutron import manager
from neutron.plugins.ml2.drivers.ovn.agent import neutron_agent
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.extensions import \
    placement as ovn_client_placement
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import worker
from neutron.plugins.ml2.drivers import type_geneve  # noqa
from neutron import service  # noqa
from neutron.services.logapi.drivers.ovn import driver as log_driver
from neutron.tests import base
from neutron.tests.common import base as common_base
from neutron.tests.common import helpers
from neutron.tests.functional.resources import process
from neutron.tests.unit.extensions import test_securitygroup
from neutron.tests.unit.plugins.ml2 import test_plugin
import neutron.wsgi

LOG = log.getLogger(__name__)

# This is the directory from which infra fetches log files for functional tests
DEFAULT_LOG_DIR = os.path.join(helpers.get_test_log_path(),
                               'dsvm-functional-logs')


def config_decorator(method_to_decorate, config_tuples):
    def wrapper(*args, **kwargs):
        method_to_decorate(*args, **kwargs)
        for config_tuple in config_tuples:
            cfg.CONF.set_override(*config_tuple)
    return wrapper


class BaseLoggingTestCase(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        # NOTE(slaweq): Because of issue with stestr and Python3, we need
        # to avoid too much output to be produced during tests, so we will
        # ignore python warnings here
        warnings.simplefilter("ignore")
        base.setup_test_logging(
            cfg.CONF, DEFAULT_LOG_DIR, "%s.txt" % self.id())
        cfg.CONF.set_override('use_helper_for_ns_read', False, group='AGENT')


class BaseSudoTestCase(BaseLoggingTestCase):
    """Base class for tests requiring invocation of commands via a root helper.

    This class skips (during setUp) its tests unless sudo is enabled, ie:
    OS_SUDO_TESTING is set to '1' or 'True' in the test execution environment.
    This is intended to allow developers to run the functional suite (e.g. tox
    -e functional) without test failures if sudo invocations are not allowed.

    Running sudo tests in the upstream gate jobs
    (*-neutron-dsvm-functional) requires the additional step of
    setting OS_ROOTWRAP_CMD to the rootwrap command configured by
    devstack, e.g.

      sudo /usr/local/bin/neutron-rootwrap /etc/neutron/rootwrap.conf

    Gate jobs do not allow invocations of sudo without rootwrap to
    ensure that rootwrap configuration gets as much testing as
    possible.
    """

    def setUp(self):
        super(BaseSudoTestCase, self).setUp()
        if not base.bool_from_env('OS_SUDO_TESTING'):
            self.skipTest('Testing with sudo is not enabled')
        self.setup_rootwrap()
        config.setup_privsep()
        self._override_default_config()

    @common_base.no_skip_on_missing_deps
    def check_command(self, cmd, error_text, skip_msg, run_as_root=False):
        try:
            utils.execute(cmd, run_as_root=run_as_root)
        except RuntimeError as e:
            if error_text in str(e):
                self.skipTest(skip_msg)
            raise

    @staticmethod
    def _override_default_config():
        # NOTE(ralonsoh): once https://review.opendev.org/#/c/641681/ is
        # merged, we should increase the default value of those new parameters.
        ovs_agent_opts = [('ovsdb_timeout', 30, 'OVS'),
                          ('ovsdb_debug', True, 'OVS'),
                          ]
        ovs_agent_decorator = config_decorator(
            ovs_conf.register_ovs_agent_opts, ovs_agent_opts)
        mock.patch.object(ovs_conf, 'register_ovs_agent_opts',
                          new=ovs_agent_decorator).start()


class TestOVNFunctionalBase(test_plugin.Ml2PluginV2TestCase,
                            BaseLoggingTestCase):

    OVS_DISTRIBUTION = 'openvswitch'
    OVN_DISTRIBUTION = 'ovn'
    OVN_SCHEMA_FILES = ['ovn-nb.ovsschema', 'ovn-sb.ovsschema']

    _mechanism_drivers = ['logger', 'ovn']
    _extension_drivers = ['port_security', 'external-gateway-multihoming']
    _counter = 0
    l3_plugin = 'neutron.services.ovn_l3.plugin.OVNL3RouterPlugin'

    def preSetUp(self):
        self.temp_dir = self.useFixture(fixtures.TempDir()).path
        self._start_ovsdb_server()

    def setUp(self, maintenance_worker=False, service_plugins=None):
        ml2_config.cfg.CONF.set_override('extension_drivers',
                                     self._extension_drivers,
                                     group='ml2')
        ml2_config.cfg.CONF.set_override('tenant_network_types',
                                     ['geneve'],
                                     group='ml2')
        ml2_config.cfg.CONF.set_override('vni_ranges',
                                     ['1:65536'],
                                     group='ml2_type_geneve')
        # ensure viable minimum is set for OVN's Geneve
        ml2_config.cfg.CONF.set_override('max_header_size', 38,
                                         group='ml2_type_geneve')
        ovn_conf.register_opts()
        ovn_conf.cfg.CONF.set_override('dns_servers',
                                       ['10.10.10.10'],
                                       group='ovn')
        ovn_conf.cfg.CONF.set_override('api_workers', 1)

        self.addCleanup(exts.PluginAwareExtensionManager.clear_instance)
        self.ovsdb_server_mgr = None
        self._service_plugins = service_plugins
        log_driver.DRIVER = None
        super(TestOVNFunctionalBase, self).setUp()
        self.test_log_dir = os.path.join(DEFAULT_LOG_DIR, self.id())
        base.setup_test_logging(
            cfg.CONF, self.test_log_dir, "testrun.txt")

        mm = directory.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers['ovn'].obj
        self.l3_plugin = directory.get_plugin(constants.L3)
        self.segments_plugin = directory.get_plugin('segments')
        # OVN does not use RPC: disable it for port-forwarding tests
        self.pf_plugin = manager.NeutronManager.load_class_for_provider(
            'neutron.service_plugins', 'port_forwarding')()
        self.pf_plugin._rpc_notifications_required = False
        self.log_plugin = directory.get_plugin(constants.LOG_API)
        if not self.log_plugin:
            self.log_plugin = manager.NeutronManager.load_class_for_provider(
                'neutron.service_plugins', 'log')()
            directory.add_plugin(constants.LOG_API, self.log_plugin)
            self.log_plugin.driver_manager.register_driver(
                self.mech_driver.log_driver)
        self.mech_driver.log_driver.plugin_driver = self.mech_driver
        self.mech_driver.log_driver._log_plugin_property = None
        for driver in self.log_plugin.driver_manager.drivers:
            if driver.name == "ovn":
                self.ovn_log_driver = driver
        if not hasattr(self, 'ovn_log_driver'):
            self.ovn_log_driver = log_driver.OVNDriver()
        self.ovn_northd_mgr = None
        self.maintenance_worker = maintenance_worker
        mock.patch(
            'neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.'
            'maintenance.MaintenanceThread').start()
        mock.patch(
            'neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.'
            'maintenance.HashRingHealthCheckPeriodics').start()
        self._start_idls()
        self._start_ovn_northd()
        self.addCleanup(self._reset_agent_cache_singleton)
        self.addCleanup(self._reset_ovn_client_placement_extension)
        plugin = directory.get_plugin()
        mock.patch.object(
            plugin, 'get_default_security_group_rules',
            return_value=copy.deepcopy(
                test_securitygroup.RULES_TEMPLATE_FOR_DEFAULT_SG)).start()

    def _reset_agent_cache_singleton(self):
        neutron_agent.AgentCache._singleton_instances = (
            weakref.WeakValueDictionary())

    def _reset_ovn_client_placement_extension(self):
        ovn_client_placement.OVNClientPlacementExtension._instance = None

    def _get_install_share_path(self):
        lookup_paths = set()
        for installation in ['local', '']:
            for distribution in [self.OVN_DISTRIBUTION, self.OVS_DISTRIBUTION]:
                exists = True
                for ovn_file in self.OVN_SCHEMA_FILES:
                    path = os.path.join(os.path.sep, 'usr', installation,
                                        'share', distribution, ovn_file)
                    exists &= os.path.isfile(path)
                    lookup_paths.add(os.path.dirname(path))
                if exists:
                    return os.path.dirname(path)
        msg = 'Either ovn-nb.ovsschema and/or ovn-sb.ovsschema are missing. '
        msg += 'Looked for schemas in paths:' + ', '.join(sorted(lookup_paths))
        raise FileNotFoundError(
                    errno.ENOENT, os.strerror(errno.ENOENT), msg)

    def get_additional_service_plugins(self):
        p = super(TestOVNFunctionalBase, self).get_additional_service_plugins()
        p.update({'revision_plugin_name': 'revisions',
                  'segments': 'neutron.services.segments.plugin.Plugin'})
        if self._service_plugins:
            p.update(self._service_plugins)
        return p

    @property
    def _ovsdb_protocol(self):
        return self.get_ovsdb_server_protocol()

    def get_ovsdb_server_protocol(self):
        return 'unix'

    def _start_ovn_northd(self):
        if not self.ovsdb_server_mgr:
            return

        def wait_for_northd():
            try:
                self.nb_api.nb_global
            except StopIteration:
                LOG.debug("NB_Global is not ready yet")
                return False

            try:
                next(iter(self.sb_api.db_list_rows('SB_Global').execute(
                    check_error=True)))
            except StopIteration:
                LOG.debug("SB_Global is not ready yet")
                return False
            except KeyError:
                # Maintenance worker doesn't register SB_Global therefore
                # we don't need to wait for it
                LOG.debug("SB_Global is not registered in this IDL")

            return True

        timeout = 20
        ovn_nb_db = self.ovsdb_server_mgr.get_ovsdb_connection_path('nb')
        ovn_sb_db = self.ovsdb_server_mgr.get_ovsdb_connection_path('sb')
        LOG.debug("Starting OVN northd")
        self.ovn_northd_mgr = self.useFixture(
            process.OvnNorthd(self.temp_dir,
                              ovn_nb_db, ovn_sb_db,
                              protocol=self._ovsdb_protocol))
        LOG.debug("OVN northd started: %r", self.ovn_northd_mgr)
        n_utils.wait_until_true(
            wait_for_northd, timeout, sleep=1,
            exception=Exception(
                "ovn-northd didn't initialize OVN DBs in %d"
                "seconds" % timeout))

    def _start_ovsdb_server(self):
        # Start 2 ovsdb-servers one each for OVN NB DB and OVN SB DB
        # ovsdb-server with OVN SB DB can be used to test the chassis up/down
        # events.
        install_share_path = self._get_install_share_path()
        self.ovsdb_server_mgr = self.useFixture(
            process.OvsdbServer(self.temp_dir, install_share_path,
                                ovn_nb_db=True, ovn_sb_db=True,
                                protocol=self._ovsdb_protocol))
        LOG.debug("OVSDB server manager instantiated: %r",
                  self.ovsdb_server_mgr)
        set_cfg = cfg.CONF.set_override
        set_cfg('ovn_nb_connection',
                self.ovsdb_server_mgr.get_ovsdb_connection_path(), 'ovn')
        set_cfg('ovn_sb_connection',
                self.ovsdb_server_mgr.get_ovsdb_connection_path(
                    db_type='sb'), 'ovn')
        set_cfg('ovn_nb_private_key', self.ovsdb_server_mgr.private_key, 'ovn')
        set_cfg('ovn_nb_certificate', self.ovsdb_server_mgr.certificate, 'ovn')
        set_cfg('ovn_nb_ca_cert', self.ovsdb_server_mgr.ca_cert, 'ovn')
        set_cfg('ovn_sb_private_key', self.ovsdb_server_mgr.private_key, 'ovn')
        set_cfg('ovn_sb_certificate', self.ovsdb_server_mgr.certificate, 'ovn')
        set_cfg('ovn_sb_ca_cert', self.ovsdb_server_mgr.ca_cert, 'ovn')

        # NOTE(mjozefcz): We can find occasional functional test
        # failures because of low timeout value - set it to 30
        # seconds, should be enough. More info: 1868110
        cfg.CONF.set_override(
            'ovsdb_connection_timeout', 30,
            'ovn')
        self.addCleanup(self._collect_processes_logs)

    def _start_idls(self):
        class TriggerCls(mock.MagicMock):
            def trigger(self):
                pass

        trigger_cls = TriggerCls()
        if self.maintenance_worker:
            trigger_cls.trigger.__self__.__class__ = worker.MaintenanceWorker
            cfg.CONF.set_override('neutron_sync_mode', 'off', 'ovn')
        else:
            trigger_cls.trigger.__self__.__class__ = neutron.wsgi.WorkerService

        self.addCleanup(self.stop)
        # NOTE(ralonsoh): do not access to the DB at exit when the SQL
        # connection is already closed, to avoid useless exception messages.
        mock.patch.object(
            self.mech_driver, '_remove_node_from_hash_ring').start()
        self.mech_driver.pre_fork_initialize(
            mock.ANY, mock.ANY, trigger_cls.trigger)

        # mech_driver.post_fork_initialize creates the IDL connections
        self.mech_driver.post_fork_initialize(
            mock.ANY, mock.ANY, trigger_cls.trigger)

        self.nb_api = self.mech_driver.nb_ovn
        self.sb_api = self.mech_driver.sb_ovn

    def _collect_processes_logs(self):
        timestamp = datetime.now().strftime('%y-%m-%d_%H-%M-%S')
        for database in ("nb", "sb"):
            for file_suffix in ("log", "db"):
                src_filename = "ovn_%(db)s.%(suffix)s" % {
                    'db': database,
                    'suffix': file_suffix
                }
                dst_filename = "ovn_%(db)s-%(timestamp)s.%(suffix)s" % {
                    'db': database,
                    'suffix': file_suffix,
                    'timestamp': timestamp,
                }
                self._copy_log_file(src_filename, dst_filename)

        # Copy northd logs
        northd_log = "ovn_northd"
        dst_northd = "%(northd)s-%(timestamp)s.log" % {
            "northd": northd_log,
            "timestamp": timestamp,
        }
        self._copy_log_file("%s.log" % northd_log, dst_northd)

    def _copy_log_file(self, src_filename, dst_filename):
        """Copy log file from temporary dict to the test directory."""
        filepath = os.path.join(self.temp_dir, src_filename)
        shutil.copyfile(
            filepath, os.path.join(self.test_log_dir, dst_filename))

    def stop(self):
        if self.maintenance_worker:
            self.mech_driver.nb_synchronizer.stop()
            self.mech_driver.sb_synchronizer.stop()
        for ovn_conn in (self.mech_driver.nb_ovn.ovsdb_connection,
                         self.mech_driver.sb_ovn.ovsdb_connection):
            try:
                ovn_conn.stop(timeout=10)
            except Exception:  # pylint:disable=bare-except
                pass

    def restart(self):
        self.stop()

        if self.ovsdb_server_mgr:
            self.ovsdb_server_mgr.stop()
        if self.ovn_northd_mgr:
            self.ovn_northd_mgr.stop()

        self.ovsdb_server_mgr.delete_dbs()
        self._start_ovsdb_server()
        self._start_idls()
        self._start_ovn_northd()

    def add_fake_chassis(self, host, physical_nets=None, external_ids=None,
                         name=None, azs=None, enable_chassis_as_gw=False,
                         enable_chassis_as_extport=False, other_config=None):
        def append_cms_options(ext_ids, value):
            if 'ovn-cms-options' not in ext_ids:
                ext_ids['ovn-cms-options'] = value
            else:
                ext_ids['ovn-cms-options'] += ',' + value

        physical_nets = physical_nets or []
        external_ids = external_ids or {}
        other_config = other_config or {}
        if azs is None:
            azs = ['ovn']
        if azs:
            append_cms_options(other_config, 'availability-zones=')
            other_config['ovn-cms-options'] += ':'.join(azs)
        if enable_chassis_as_gw:
            append_cms_options(other_config, 'enable-chassis-as-gw')
        if enable_chassis_as_extport:
            append_cms_options(other_config, 'enable-chassis-as-extport-host')

        bridge_mapping = ",".join(["%s:br-provider%s" % (phys_net, i)
                                  for i, phys_net in enumerate(physical_nets)])
        if name is None:
            name = uuidutils.generate_uuid()
        other_config['ovn-bridge-mappings'] = bridge_mapping
        # We'll be using different IP addresses every time for the Encap of
        # the fake chassis as the SB schema doesn't allow to have two entries
        # with same (ip,type) pairs as of OVS 2.11. This shouldn't have any
        # impact as the tunnels won't get created anyways since ovn-controller
        # is not running. Ideally we shouldn't be creating more than 255
        # fake chassis but from the SB db point of view, 'ip' column can be
        # any string so we could add entries with ip='172.24.4.1000'.
        self._counter += 1
        chassis = self.sb_api.chassis_add(
            name, ['geneve'], '172.24.4.%d' % self._counter,
            external_ids=external_ids, hostname=host,
            other_config=other_config).execute(check_error=True)
        nb_cfg_timestamp = timeutils.utcnow_ts() * 1000
        self.sb_api.db_create(
            'Chassis_Private', name=name, external_ids=external_ids,
            chassis=chassis.uuid, nb_cfg_timestamp=nb_cfg_timestamp
        ).execute(check_error=True)
        return name

    def del_fake_chassis(self, chassis, if_exists=True):
        self.sb_api.chassis_del(
            chassis, if_exists=if_exists).execute(check_error=True)
        try:
            self.sb_api.db_destroy(
                'Chassis_Private', chassis).execute(check_error=True)
        except idlutils.RowNotFound:
            # NOTE(ykarel ): ovsdbapp >= 2.6.1 handles Chassis_Private
            # record delete with chassis
            # try/except can be dropped when neutron requirements.txt
            # include ovsdbapp>=2.6.1
            pass

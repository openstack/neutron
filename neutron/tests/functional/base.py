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

from datetime import datetime
import errno
import os
import shutil
from unittest import mock
import warnings

import fixtures
from neutron_lib import fixture
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_db import exception as os_db_exc
from oslo_db.sqlalchemy import provision
from oslo_log import log
from oslo_utils import uuidutils

from neutron.agent.linux import utils
from neutron.api import extensions as exts
from neutron.conf.agent import common as config
from neutron.conf.agent import ovs_conf
from neutron.conf.plugins.ml2 import config as ml2_config
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
# Load all the models to register them into SQLAlchemy metadata before using
# the SqlFixture
from neutron.db import models  # noqa
from neutron import manager
from neutron.plugins.ml2.drivers.ovn.agent import neutron_agent
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import worker
from neutron.plugins.ml2.drivers import type_geneve  # noqa
from neutron import service  # noqa
from neutron.tests import base
from neutron.tests.common import base as common_base
from neutron.tests.common import helpers
from neutron.tests.functional.resources import process
from neutron.tests.unit.plugins.ml2 import test_plugin
import neutron.wsgi

LOG = log.getLogger(__name__)

# This is the directory from which infra fetches log files for functional tests
DEFAULT_LOG_DIR = os.path.join(helpers.get_test_log_path(),
                               'dsvm-functional-logs')
SQL_FIXTURE_LOCK = 'sql_fixture_lock'


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


class OVNSqlFixture(fixture.StaticSqlFixture):

    @classmethod
    @lockutils.synchronized(SQL_FIXTURE_LOCK)
    def _init_resources(cls):
        cls.schema_resource = provision.SchemaResource(
            provision.DatabaseResource("sqlite"),
            cls._generate_schema, teardown=False)
        dependency_resources = {}
        for name, resource in cls.schema_resource.resources:
            dependency_resources[name] = resource.getResource()
        cls.schema_resource.make(dependency_resources)
        cls.engine = dependency_resources['database'].engine

    def _delete_from_schema(self, engine):
        try:
            super(OVNSqlFixture, self)._delete_from_schema(engine)
        except os_db_exc.DBNonExistentTable:
            pass


class TestOVNFunctionalBase(test_plugin.Ml2PluginV2TestCase,
                            BaseLoggingTestCase):

    OVS_DISTRIBUTION = 'openvswitch'
    OVN_DISTRIBUTION = 'ovn'
    OVN_SCHEMA_FILES = ['ovn-nb.ovsschema', 'ovn-sb.ovsschema']

    _mechanism_drivers = ['logger', 'ovn']
    _extension_drivers = ['port_security']
    _counter = 0
    l3_plugin = 'neutron.services.ovn_l3.plugin.OVNL3RouterPlugin'

    def preSetUp(self):
        self.temp_dir = self.useFixture(fixtures.TempDir()).path
        self._start_ovsdb_server()

    def setUp(self, maintenance_worker=False):
        ml2_config.cfg.CONF.set_override('extension_drivers',
                                     self._extension_drivers,
                                     group='ml2')
        ml2_config.cfg.CONF.set_override('tenant_network_types',
                                     ['geneve'],
                                     group='ml2')
        ml2_config.cfg.CONF.set_override('vni_ranges',
                                     ['1:65536'],
                                     group='ml2_type_geneve')
        ovn_conf.cfg.CONF.set_override('dns_servers',
                                       ['10.10.10.10'],
                                       group='ovn')
        ovn_conf.cfg.CONF.set_override('api_workers', 1)

        self.addCleanup(exts.PluginAwareExtensionManager.clear_instance)
        self.ovsdb_server_mgr = None
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

    def _reset_agent_cache_singleton(self):
        neutron_agent.AgentCache._instance = None

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

    # FIXME(lucasagomes): Workaround for
    # https://bugs.launchpad.net/networking-ovn/+bug/1808146. We should
    # investigate and properly fix the problem. This method is just a
    # workaround to alleviate the gate for now and should not be considered
    # a proper fix.
    def _setup_database_fixtures(self):
        fixture = OVNSqlFixture()
        self.useFixture(fixture)
        self.engine = fixture.engine

    def get_additional_service_plugins(self):
        p = super(TestOVNFunctionalBase, self).get_additional_service_plugins()
        p.update({'revision_plugin_name': 'revisions'})
        p.update({'segments': 'neutron.services.segments.plugin.Plugin'})
        return p

    @property
    def _ovsdb_protocol(self):
        return self.get_ovsdb_server_protocol()

    def get_ovsdb_server_protocol(self):
        return 'unix'

    def _start_ovn_northd(self):
        if not self.ovsdb_server_mgr:
            return
        ovn_nb_db = self.ovsdb_server_mgr.get_ovsdb_connection_path('nb')
        ovn_sb_db = self.ovsdb_server_mgr.get_ovsdb_connection_path('sb')
        self.ovn_northd_mgr = self.useFixture(
            process.OvnNorthd(self.temp_dir,
                              ovn_nb_db, ovn_sb_db,
                              protocol=self._ovsdb_protocol))

    def _start_ovsdb_server(self):
        # Start 2 ovsdb-servers one each for OVN NB DB and OVN SB DB
        # ovsdb-server with OVN SB DB can be used to test the chassis up/down
        # events.
        install_share_path = self._get_install_share_path()
        self.ovsdb_server_mgr = self.useFixture(
            process.OvsdbServer(self.temp_dir, install_share_path,
                                ovn_nb_db=True, ovn_sb_db=True,
                                protocol=self._ovsdb_protocol))
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
        # seconds, should be enought. More info: 1868110
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
        mock.patch.object(self.mech_driver, '_clean_hash_ring').start()
        self.mech_driver.pre_fork_initialize(
            mock.ANY, mock.ANY, trigger_cls.trigger)

        # mech_driver.post_fork_initialize creates the IDL connections
        self.mech_driver.post_fork_initialize(
            mock.ANY, mock.ANY, trigger_cls.trigger)

        self.nb_api = self.mech_driver._nb_ovn
        self.sb_api = self.mech_driver._sb_ovn

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
        self.mech_driver._nb_ovn.ovsdb_connection.stop()
        self.mech_driver._sb_ovn.ovsdb_connection.stop()

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
                         name=None):
        physical_nets = physical_nets or []
        external_ids = external_ids or {}

        bridge_mapping = ",".join(["%s:br-provider%s" % (phys_net, i)
                                  for i, phys_net in enumerate(physical_nets)])
        if name is None:
            name = uuidutils.generate_uuid()
        external_ids['ovn-bridge-mappings'] = bridge_mapping
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
            external_ids=external_ids, hostname=host).execute(check_error=True)
        if self.sb_api.is_table_present('Chassis_Private'):
            self.sb_api.db_create(
                'Chassis_Private', name=name, external_ids=external_ids,
                chassis=chassis.uuid).execute(check_error=True)
        return name

    def del_fake_chassis(self, chassis, if_exists=True):
        self.sb_api.chassis_del(
            chassis, if_exists=if_exists).execute(check_error=True)

# Copyright 2010-2011 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Base Test Case for all Unit Tests"""

import contextlib
import gc
import logging
import os
import os.path
import sys
import weakref

import eventlet.timeout
import fixtures
import mock
from oslo.config import cfg
from oslo.messaging import conffixture as messaging_conffixture
import testtools

from neutron.common import config
from neutron.common import rpc as n_rpc
from neutron.db import agentschedulers_db
from neutron import manager
from neutron.tests import fake_notifier
from neutron.tests import post_mortem_debug


CONF = cfg.CONF
CONF.import_opt('state_path', 'neutron.common.config')
TRUE_STRING = ['True', '1']
LOG_FORMAT = "%(asctime)s %(levelname)8s [%(name)s] %(message)s"

ROOTDIR = os.path.dirname(__file__)
ETCDIR = os.path.join(ROOTDIR, 'etc')


def etcdir(*p):
    return os.path.join(ETCDIR, *p)


def fake_use_fatal_exceptions(*args):
    return True


def fake_consume_in_threads(self):
    return []


class BaseTestCase(testtools.TestCase):

    def cleanup_core_plugin(self):
        """Ensure that the core plugin is deallocated."""
        nm = manager.NeutronManager
        if not nm.has_instance():
            return

        #TODO(marun) Fix plugins that do not properly initialize notifiers
        agentschedulers_db.AgentSchedulerDbMixin.agent_notifiers = {}

        # Perform a check for deallocation only if explicitly
        # configured to do so since calling gc.collect() after every
        # test increases test suite execution time by ~50%.
        check_plugin_deallocation = (
            os.environ.get('OS_CHECK_PLUGIN_DEALLOCATION') in TRUE_STRING)
        if check_plugin_deallocation:
            plugin = weakref.ref(nm._instance.plugin)

        nm.clear_instance()

        if check_plugin_deallocation:
            gc.collect()

            #TODO(marun) Ensure that mocks are deallocated?
            if plugin() and not isinstance(plugin(), mock.Base):
                self.fail('The plugin for this test was not deallocated.')

    def setup_coreplugin(self, core_plugin=None):
        if core_plugin is not None:
            cfg.CONF.set_override('core_plugin', core_plugin)

    def setup_notification_driver(self, notification_driver=None):
        self.addCleanup(fake_notifier.reset)
        if notification_driver is None:
            notification_driver = [fake_notifier.__name__]
        cfg.CONF.set_override("notification_driver", notification_driver)

    @staticmethod
    def config_parse(conf=None, args=None):
        """Create the default configurations."""
        # neutron.conf.test includes rpc_backend which needs to be cleaned up
        if args is None:
            args = ['--config-file', etcdir('neutron.conf.test')]
        if conf is None:
            config.init(args=args)
        else:
            conf(args)

    def setUp(self):
        super(BaseTestCase, self).setUp()

        # Ensure plugin cleanup is triggered last so that
        # test-specific cleanup has a chance to release references.
        self.addCleanup(self.cleanup_core_plugin)

        # Configure this first to ensure pm debugging support for setUp()
        if os.environ.get('OS_POST_MORTEM_DEBUG') in TRUE_STRING:
            self.addOnException(post_mortem_debug.exception_handler)

        if os.environ.get('OS_DEBUG') in TRUE_STRING:
            _level = logging.DEBUG
        else:
            _level = logging.INFO
        capture_logs = os.environ.get('OS_LOG_CAPTURE') in TRUE_STRING
        if not capture_logs:
            logging.basicConfig(format=LOG_FORMAT, level=_level)
        self.log_fixture = self.useFixture(
            fixtures.FakeLogger(
                format=LOG_FORMAT,
                level=_level,
                nuke_handlers=capture_logs,
            ))

        # suppress all but errors here
        self.useFixture(
            fixtures.FakeLogger(
                name='neutron.api.extensions',
                format=LOG_FORMAT,
                level=logging.ERROR,
                nuke_handlers=capture_logs,
            ))

        test_timeout = int(os.environ.get('OS_TEST_TIMEOUT', 0))
        if test_timeout == -1:
            test_timeout = 0
        if test_timeout > 0:
            self.useFixture(fixtures.Timeout(test_timeout, gentle=True))

        # If someone does use tempfile directly, ensure that it's cleaned up
        self.useFixture(fixtures.NestedTempfile())
        self.useFixture(fixtures.TempHomeDir())

        self.temp_dir = self.useFixture(fixtures.TempDir()).path
        cfg.CONF.set_override('state_path', self.temp_dir)

        self.addCleanup(mock.patch.stopall)
        self.addCleanup(CONF.reset)

        if os.environ.get('OS_STDOUT_CAPTURE') in TRUE_STRING:
            stdout = self.useFixture(fixtures.StringStream('stdout')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stdout', stdout))
        if os.environ.get('OS_STDERR_CAPTURE') in TRUE_STRING:
            stderr = self.useFixture(fixtures.StringStream('stderr')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stderr', stderr))
        self.useFixture(fixtures.MonkeyPatch(
            'neutron.common.exceptions.NeutronException.use_fatal_exceptions',
            fake_use_fatal_exceptions))

        # don't actually start RPC listeners when testing
        self.useFixture(fixtures.MonkeyPatch(
            'neutron.common.rpc.Connection.consume_in_threads',
            fake_consume_in_threads))

        self.useFixture(fixtures.MonkeyPatch(
            'oslo.messaging.Notifier', fake_notifier.FakeNotifier))

        self.messaging_conf = messaging_conffixture.ConfFixture(CONF)
        self.messaging_conf.transport_driver = 'fake'
        self.messaging_conf.response_timeout = 15
        self.useFixture(self.messaging_conf)

        self.addCleanup(n_rpc.clear_extra_exmods)
        n_rpc.add_extra_exmods('neutron.test')

        self.addCleanup(n_rpc.cleanup)
        n_rpc.init(CONF)

        if sys.version_info < (2, 7) and getattr(self, 'fmt', '') == 'xml':
            raise self.skipException('XML Testing Skipped in Py26')

    def config(self, **kw):
        """Override some configuration values.

        The keyword arguments are the names of configuration options to
        override and their values.

        If a group argument is supplied, the overrides are applied to
        the specified configuration option group.

        All overrides are automatically cleared at the end of the current
        test by the fixtures cleanup process.
        """
        group = kw.pop('group', None)
        for k, v in kw.iteritems():
            CONF.set_override(k, v, group)

    @contextlib.contextmanager
    def assert_max_execution_time(self, max_execution_time=5):
        with eventlet.timeout.Timeout(max_execution_time, False):
            yield
            return
        self.fail('Execution of this test timed out')

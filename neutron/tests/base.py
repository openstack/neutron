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

"""Base test case for tests that do not rely on Tempest.

To change behavoir that is common to all tests, please target
the neutron.tests.sub_base module instead.

If a test needs to import a dependency like Tempest, see
neutron.tests.sub_base for a base test class that can be used without
errors due to duplicate configuration definitions.
"""

import logging as std_logging
import os.path

import fixtures
from oslo_concurrency.fixture import lockutils
from oslo_config import cfg
from oslo_messaging import conffixture as messaging_conffixture

from neutron.common import config
from neutron.common import rpc as n_rpc
from neutron.tests import fake_notifier
from neutron.tests import sub_base


CONF = cfg.CONF
CONF.import_opt('state_path', 'neutron.common.config')
LOG_FORMAT = sub_base.LOG_FORMAT

ROOTDIR = os.path.dirname(__file__)
ETCDIR = os.path.join(ROOTDIR, 'etc')


def etcdir(*p):
    return os.path.join(ETCDIR, *p)


def fake_use_fatal_exceptions(*args):
    return True


def fake_consume_in_threads(self):
    return []


bool_from_env = sub_base.bool_from_env


class BaseTestCase(sub_base.SubBaseTestCase):

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

        # suppress all but errors here
        capture_logs = bool_from_env('OS_LOG_CAPTURE')
        self.useFixture(
            fixtures.FakeLogger(
                name='neutron.api.extensions',
                format=LOG_FORMAT,
                level=std_logging.ERROR,
                nuke_handlers=capture_logs,
            ))

        self.useFixture(lockutils.ExternalLockFixture())

        cfg.CONF.set_override('state_path', self.get_default_temp_dir().path)

        self.addCleanup(CONF.reset)

        self.useFixture(fixtures.MonkeyPatch(
            'neutron.common.exceptions.NeutronException.use_fatal_exceptions',
            fake_use_fatal_exceptions))

        self.setup_rpc_mocks()
        self.setup_config()

    def get_new_temp_dir(self):
        """Create a new temporary directory.

        :returns fixtures.TempDir
        """
        return self.useFixture(fixtures.TempDir())

    def get_default_temp_dir(self):
        """Create a default temporary directory.

        Returns the same directory during the whole test case.

        :returns fixtures.TempDir
        """
        if not hasattr(self, '_temp_dir'):
            self._temp_dir = self.get_new_temp_dir()
        return self._temp_dir

    def get_temp_file_path(self, filename, root=None):
        """Returns an absolute path for a temporary file.

        If root is None, the file is created in default temporary directory. It
        also creates the directory if it's not initialized yet.

        If root is not None, the file is created inside the directory passed as
        root= argument.

        :param filename: filename
        :type filename: string
        :param root: temporary directory to create a new file in
        :type root: fixtures.TempDir
        :returns absolute file path string
        """
        root = root or self.get_default_temp_dir()
        return root.join(filename)

    def setup_rpc_mocks(self):
        # don't actually start RPC listeners when testing
        self.useFixture(fixtures.MonkeyPatch(
            'neutron.common.rpc.Connection.consume_in_threads',
            fake_consume_in_threads))

        self.useFixture(fixtures.MonkeyPatch(
            'oslo_messaging.Notifier', fake_notifier.FakeNotifier))

        self.messaging_conf = messaging_conffixture.ConfFixture(CONF)
        self.messaging_conf.transport_driver = 'fake'
        # NOTE(russellb) We want all calls to return immediately.
        self.messaging_conf.response_timeout = 0
        self.useFixture(self.messaging_conf)

        self.addCleanup(n_rpc.clear_extra_exmods)
        n_rpc.add_extra_exmods('neutron.test')

        self.addCleanup(n_rpc.cleanup)
        n_rpc.init(CONF)

    def setup_config(self, args=None):
        """Tests that need a non-default config can override this method."""
        self.config_parse(args=args)

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

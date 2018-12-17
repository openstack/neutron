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

import os
import warnings

from oslo_config import cfg

from neutron.agent.linux import utils
from neutron.conf.agent import common as config
from neutron.tests import base
from neutron.tests.common import base as common_base
from neutron.tests.common import helpers

# This is the directory from which infra fetches log files for functional tests
DEFAULT_LOG_DIR = os.path.join(helpers.get_test_log_path(),
                               'dsvm-functional-logs')


class BaseLoggingTestCase(base.BaseTestCase):
    def setUp(self):
        super(BaseLoggingTestCase, self).setUp()
        # NOTE(slaweq): Because of issue with stestr and Python3, we need
        # to avoid too much output to be produced during tests, so we will
        # ignore python warnings here
        warnings.simplefilter("ignore")
        base.setup_test_logging(
            cfg.CONF, DEFAULT_LOG_DIR, "%s.txt" % self.id())


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

    @common_base.no_skip_on_missing_deps
    def check_command(self, cmd, error_text, skip_msg, run_as_root=False):
        try:
            utils.execute(cmd, run_as_root=run_as_root)
        except RuntimeError as e:
            if error_text in str(e):
                self.skipTest(skip_msg)
            raise

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

from oslo_config import cfg

from neutron.agent.common import config
from neutron.agent.linux import utils
from neutron.tests import base

SUDO_CMD = 'sudo -n'


class BaseSudoTestCase(base.BaseTestCase):
    """
    Base class for tests requiring invocation of commands via a root helper.

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

        self.fail_on_missing_deps = (
            base.bool_from_env('OS_FAIL_ON_MISSING_DEPS'))

        config.register_root_helper(cfg.CONF)
        self.config(group='AGENT',
                    root_helper=os.environ.get('OS_ROOTWRAP_CMD', SUDO_CMD))
        self.config(group='AGENT',
                    root_helper_daemon=os.environ.get(
                        'OS_ROOTWRAP_DAEMON_CMD'))

    def check_command(self, cmd, error_text, skip_msg, run_as_root=False):
        try:
            utils.execute(cmd, run_as_root=run_as_root)
        except RuntimeError as e:
            if error_text in str(e) and not self.fail_on_missing_deps:
                self.skipTest(skip_msg)
            raise

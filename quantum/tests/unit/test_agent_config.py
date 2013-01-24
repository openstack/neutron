# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import unittest2 as unittest

from quantum.agent.common import config
from quantum.agent.common import validate
from quantum.openstack.common import cfg


def test_setup_conf():
    conf = config.setup_conf()
    assert conf.state_path.endswith('/var/lib/quantum')


class TestCoreConfigOptions(unittest.TestCase):

    def setUp(self):
        self._saved_core_plugin = cfg.CONF.core_plugin

    def tearDown(self):
        cfg.CONF.set_override('core_plugin', self._saved_core_plugin)

    def test_missing_required_core_option(self):
        with self.assertRaises(Exception) as ex:
            validate.core_config_options(cfg.CONF)

    def test_have_required_core_option(self):
        cfg.CONF.set_override('core_plugin', 'some_core_plugin_option')
        validate.core_config_options(cfg.CONF)

# Copyright 2013 Nicira Networks, Inc.
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
#

from oslo.config import cfg

from quantum.plugins.nicira.nicira_nvp_plugin.common import config  # noqa
from quantum.tests import base


class ConfigurationTest(base.BaseTestCase):

    def test_defaults(self):
        self.assertEqual(64, cfg.CONF.NVP.max_lp_per_bridged_ls)
        self.assertEqual(256, cfg.CONF.NVP.max_lp_per_overlay_ls)
        self.assertEqual(5, cfg.CONF.NVP.concurrent_connections)

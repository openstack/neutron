# Copyright 2015 Red Hat, Inc.
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

import mock
from oslo_config import cfg

from neutron.cmd import sanity_check
from neutron.tests import base


class TestSanityCheck(base.BaseTestCase):

    def test_setup_conf_and_enable_test_from_config(self):
        # Verify that configuration can be successfully imported and tests are
        # correctly loaded, based on the registered configuration parameters.
        with mock.patch.object(sanity_check, 'cfg') as mock_cfg:
            mock_cfg.CONF = cfg.ConfigOpts()
            sanity_check.cfg.CONF.register_cli_opts(sanity_check.OPTS)
            sanity_check.setup_conf()
            sanity_check.enable_tests_from_config()

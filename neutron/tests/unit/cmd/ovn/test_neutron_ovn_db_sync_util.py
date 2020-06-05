# Copyright 2020 Canonical Ltd
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

from oslo_config import cfg

from neutron.cmd.ovn import neutron_ovn_db_sync_util as util
from neutron.tests import base


class TestNeutronOVNDBSyncUtil(base.BaseTestCase):

    def test_setup_conf(self):
        # the code under test will fail because of the cfg.conf alredy being
        # initialized by the BaseTestCase setUp method. Reset.
        cfg.CONF.reset()
        util.setup_conf()
        # The sync tool will fail if these config options are at their default
        # value. Validate that the setup code overrides them. LP: #1882020
        self.assertFalse(cfg.CONF.notify_nova_on_port_status_changes)
        self.assertFalse(cfg.CONF.notify_nova_on_port_data_changes)

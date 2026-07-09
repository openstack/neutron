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

from unittest import mock

from oslo_config import cfg

from neutron.cmd.ovn import neutron_ovn_db_sync_util as util
from neutron.tests import base


class TestNeutronOVNDBSyncUtil(base.BaseTestCase):

    def test_setup_conf(self):
        # the code under test will fail because of the cfg.conf already being
        # initialized by the BaseTestCase setUp method. Reset.
        cfg.CONF.reset()
        util.setup_conf()
        # The sync tool will fail if these config options are at their default
        # value. Validate that the setup code overrides them. LP: #1882020
        self.assertFalse(cfg.CONF.notify_nova_on_port_status_changes)
        self.assertFalse(cfg.CONF.notify_nova_on_port_data_changes)

    def test_load_db_migration_drivers_calls_callable_plugin(self):
        migration_fn = mock.Mock()
        fake_ext = mock.Mock()
        fake_ext.name = 'neutron'
        fake_ext.plugin = migration_fn

        with mock.patch(
                'stevedore.enabled.EnabledExtensionManager') as mock_mgr_cls:
            mock_mgr = mock.Mock()
            mock_mgr_cls.return_value = mock_mgr
            mock_mgr.__iter__ = mock.Mock(return_value=iter([fake_ext]))

            util.load_db_migration_drivers()

        mock_mgr_cls.assert_called_once_with(
            'neutron.ovn.db_migration',
            check_func=mock.ANY,
            invoke_on_load=False)

        # Verify the check_func accepts a callable (non-class) plugin without
        # raising TypeError from issubclass()
        check_func = mock_mgr_cls.call_args[1]['check_func']
        self.assertTrue(check_func(fake_ext))

    def test_load_db_migration_drivers_filters_by_name(self):
        fake_ext_a = mock.Mock()
        fake_ext_a.name = 'neutron'
        fake_ext_b = mock.Mock()
        fake_ext_b.name = 'other'

        with mock.patch(
                'stevedore.enabled.EnabledExtensionManager') as mock_mgr_cls:
            util.load_db_migration_drivers(driver_name='neutron')

        check_func = mock_mgr_cls.call_args[1]['check_func']
        self.assertTrue(check_func(fake_ext_a))
        self.assertFalse(check_func(fake_ext_b))

    def test_migrate_neutron_dbs_to_ovn_calls_plugin(self):
        migration_fn = mock.Mock()
        fake_ext = mock.Mock()
        fake_ext.name = 'neutron'
        fake_ext.plugin = migration_fn

        util.migrate_neutron_dbs_to_ovn(fake_ext)

        migration_fn.assert_called_once_with()

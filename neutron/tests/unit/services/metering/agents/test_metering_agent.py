# Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
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

import mock
from oslo_config import cfg

from neutron.openstack.common import uuidutils
from neutron.services.metering.agents import metering_agent
from neutron.tests import base
from neutron.tests import fake_notifier


_uuid = uuidutils.generate_uuid

TENANT_ID = _uuid()
LABEL_ID = _uuid()
ROUTERS = [{'status': 'ACTIVE',
            'name': 'router1',
            'gw_port_id': None,
            'admin_state_up': True,
            'tenant_id': TENANT_ID,
            '_metering_labels': [{'rules': [],
                                  'id': LABEL_ID}],
            'id': _uuid()}]

ROUTERS_WITH_RULE = [{'status': 'ACTIVE',
                      'name': 'router1',
                      'gw_port_id': None,
                      'admin_state_up': True,
                      'tenant_id': TENANT_ID,
                      '_metering_labels': [{'rule': {},
                                            'id': LABEL_ID}],
                      'id': _uuid()}]


class TestMeteringOperations(base.BaseTestCase):

    def setUp(self):
        super(TestMeteringOperations, self).setUp()
        cfg.CONF.register_opts(metering_agent.MeteringAgent.Opts)

        self.noop_driver = ('neutron.services.metering.drivers.noop.'
                            'noop_driver.NoopMeteringDriver')
        cfg.CONF.set_override('driver', self.noop_driver)
        cfg.CONF.set_override('measure_interval', 0)
        cfg.CONF.set_override('report_interval', 0)

        self.setup_notification_driver()

        metering_rpc = ('neutron.services.metering.agents.metering_agent.'
                        'MeteringPluginRpc._get_sync_data_metering')
        self.metering_rpc_patch = mock.patch(metering_rpc, return_value=[])
        self.metering_rpc_patch.start()

        self.driver_patch = mock.patch(self.noop_driver, spec=True)
        self.driver_patch.start()

        loopingcall_patch = mock.patch(
            'neutron.openstack.common.loopingcall.FixedIntervalLoopingCall')
        loopingcall_patch.start()

        self.agent = metering_agent.MeteringAgent('my agent', cfg.CONF)
        self.driver = self.agent.metering_driver

    def test_add_metering_label(self):
        self.agent.add_metering_label(None, ROUTERS)
        self.assertEqual(self.driver.add_metering_label.call_count, 1)

    def test_remove_metering_label(self):
        self.agent.remove_metering_label(None, ROUTERS)
        self.assertEqual(self.driver.remove_metering_label.call_count, 1)

    def test_update_metering_label_rule(self):
        self.agent.update_metering_label_rules(None, ROUTERS)
        self.assertEqual(self.driver.update_metering_label_rules.call_count, 1)

    def test_add_metering_label_rule(self):
        self.agent.add_metering_label_rule(None, ROUTERS_WITH_RULE)
        self.assertEqual(self.driver.add_metering_label_rule.call_count, 1)

    def test_remove_metering_label_rule(self):
        self.agent.remove_metering_label_rule(None, ROUTERS_WITH_RULE)
        self.assertEqual(self.driver.remove_metering_label_rule.call_count, 1)

    def test_routers_updated(self):
        self.agent.routers_updated(None, ROUTERS)
        self.assertEqual(self.driver.update_routers.call_count, 1)

    def test_get_traffic_counters(self):
        self.agent._get_traffic_counters(None, ROUTERS)
        self.assertEqual(self.driver.get_traffic_counters.call_count, 1)

    def test_notification_report(self):
        self.agent.routers_updated(None, ROUTERS)

        self.driver.get_traffic_counters.return_value = {LABEL_ID:
                                                         {'pkts': 88,
                                                          'bytes': 444}}
        self.agent._metering_loop()

        self.assertNotEqual(len(fake_notifier.NOTIFICATIONS), 0)
        for n in fake_notifier.NOTIFICATIONS:
            if n['event_type'] == 'l3.meter':
                break

        self.assertEqual(n['event_type'], 'l3.meter')

        payload = n['payload']
        self.assertEqual(payload['tenant_id'], TENANT_ID)
        self.assertEqual(payload['label_id'], LABEL_ID)
        self.assertEqual(payload['pkts'], 88)
        self.assertEqual(payload['bytes'], 444)

    def test_router_deleted(self):
        label_id = _uuid()
        self.driver.get_traffic_counters = mock.MagicMock()
        self.driver.get_traffic_counters.return_value = {label_id:
                                                         {'pkts': 44,
                                                          'bytes': 222}}
        self.agent._add_metering_info = mock.MagicMock()

        self.agent.routers_updated(None, ROUTERS)
        self.agent.router_deleted(None, ROUTERS[0]['id'])

        self.assertEqual(self.agent._add_metering_info.call_count, 1)
        self.assertEqual(self.driver.remove_router.call_count, 1)

        self.agent._add_metering_info.assert_called_with(label_id, 44, 222)

    @mock.patch('time.time')
    def _test_purge_metering_info(self, current_timestamp, is_empty,
                                  mock_time):
        mock_time.return_value = current_timestamp
        self.agent.metering_infos = {'fake': {'last_update': 1}}
        self.config(report_interval=1)

        self.agent._purge_metering_info()
        self.assertEqual(0 if is_empty else 1, len(self.agent.metering_infos))
        self.assertEqual(1, mock_time.call_count)

    def test_purge_metering_info(self):
        # 1 < 2 - 1 -> False
        self._test_purge_metering_info(2, False)

    def test_purge_metering_info_delete(self):
        # 1 < 3 - 1 -> False
        self._test_purge_metering_info(3, True)

    @mock.patch('time.time')
    def _test_add_metering_info(self, expected_info, current_timestamp,
                                mock_time):
        mock_time.return_value = current_timestamp
        actual_info = self.agent._add_metering_info('fake_label_id', 1, 1)
        self.assertEqual(1, len(self.agent.metering_infos))
        self.assertEqual(expected_info, actual_info)
        self.assertEqual(expected_info,
                         self.agent.metering_infos['fake_label_id'])
        self.assertEqual(1, mock_time.call_count)

    def test_add_metering_info_create(self):
        expected_info = {'bytes': 1, 'pkts': 1, 'time': 0, 'first_update': 1,
                         'last_update': 1}
        self._test_add_metering_info(expected_info, 1)

    def test_add_metering_info_update(self):
        expected_info = {'bytes': 1, 'pkts': 1, 'time': 0, 'first_update': 1,
                         'last_update': 1}
        self.agent.metering_infos = {'fake_label_id': expected_info}
        expected_info.update({'bytes': 2, 'pkts': 2, 'time': 1,
                              'last_update': 2})
        self._test_add_metering_info(expected_info, 2)


class TestMeteringDriver(base.BaseTestCase):
    def setUp(self):
        super(TestMeteringDriver, self).setUp()
        cfg.CONF.register_opts(metering_agent.MeteringAgent.Opts)

        self.noop_driver = ('neutron.services.metering.drivers.noop.'
                            'noop_driver.NoopMeteringDriver')
        cfg.CONF.set_override('driver', self.noop_driver)

        self.agent = metering_agent.MeteringAgent('my agent', cfg.CONF)
        self.driver = mock.Mock()
        self.agent.metering_driver = self.driver

    def test_add_metering_label_with_bad_driver_impl(self):
        del self.driver.add_metering_label

        with mock.patch.object(metering_agent, 'LOG') as log:
            self.agent.add_metering_label(None, ROUTERS)
            log.exception.assert_called_with(mock.ANY,
                                             {'driver': self.noop_driver,
                                              'func': 'add_metering_label'})

    def test_add_metering_label_runtime_error(self):
        self.driver.add_metering_label.side_effect = RuntimeError

        with mock.patch.object(metering_agent, 'LOG') as log:
            self.agent.add_metering_label(None, ROUTERS)
            log.exception.assert_called_with(mock.ANY,
                                             {'driver': self.noop_driver,
                                              'func':
                                              'add_metering_label'})

    def test_init_chain(self):
        with mock.patch('neutron.openstack.common.'
                        'periodic_task.PeriodicTasks.__init__') as init:
            metering_agent.MeteringAgent('my agent', cfg.CONF)
        init.assert_called_once_with()

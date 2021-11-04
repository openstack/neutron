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

from unittest import mock

from neutron_lib.tests.unit import fake_notifier
from oslo_config import cfg
from oslo_utils import fixture as utils_fixture
from oslo_utils import timeutils
from oslo_utils import uuidutils

from neutron.conf.services import metering_agent as metering_agent_config
from neutron.services.metering.agents import metering_agent
from neutron.tests import base

_uuid = uuidutils.generate_uuid

PROJECT_ID = _uuid()
LABEL_ID = _uuid()
ROUTERS = [{'status': 'ACTIVE',
            'name': 'router1',
            'gw_port_id': None,
            'admin_state_up': True,
            'project_id': PROJECT_ID,
            '_metering_labels': [{'rules': [],
                                  'id': LABEL_ID}],
            'id': _uuid()}]

ROUTERS_WITH_RULE = [{'status': 'ACTIVE',
                      'name': 'router1',
                      'gw_port_id': None,
                      'admin_state_up': True,
                      'project_id': PROJECT_ID,
                      '_metering_labels': [{'rule': {},
                                            'id': LABEL_ID}],
                      'id': _uuid()}]


class TestMeteringOperations(base.BaseTestCase):

    def setUp(self):
        super(TestMeteringOperations, self).setUp()
        metering_agent_config.register_metering_agent_opts()

        self.noop_driver = ('neutron.services.metering.drivers.noop.'
                            'noop_driver.NoopMeteringDriver')
        cfg.CONF.set_override('driver', 'noop')
        cfg.CONF.set_override('measure_interval', 0)
        cfg.CONF.set_override('report_interval', 0)
        cfg.CONF.set_override('granular_traffic_data', False)

        self.setup_notification_driver()

        metering_rpc = ('neutron.services.metering.agents.metering_agent.'
                        'MeteringPluginRpc._get_sync_data_metering')
        self.metering_rpc_patch = mock.patch(metering_rpc, return_value=[])
        self.metering_rpc_patch.start()

        self.driver_patch = mock.patch(self.noop_driver, spec=True)
        self.driver_patch.start()

        loopingcall_patch = mock.patch(
            'oslo_service.loopingcall.FixedIntervalLoopingCall')
        loopingcall_patch.start()

        self.agent = metering_agent.MeteringAgent('my agent', cfg.CONF)
        self.driver = self.agent.metering_driver

    def test_add_metering_label(self):
        self.agent.add_metering_label(None, ROUTERS)
        self.assertEqual(1, self.driver.add_metering_label.call_count)

    def test_remove_metering_label(self):
        self.agent.remove_metering_label(None, ROUTERS)
        self.assertEqual(1, self.driver.remove_metering_label.call_count)

    def test_update_metering_label_rule(self):
        self.agent.update_metering_label_rules(None, ROUTERS)
        self.assertEqual(1, self.driver.update_metering_label_rules.call_count)

    def test_add_metering_label_rule(self):
        self.agent.add_metering_label_rule(None, ROUTERS_WITH_RULE)
        self.assertEqual(1, self.driver.add_metering_label_rule.call_count)

    def test_remove_metering_label_rule(self):
        self.agent.remove_metering_label_rule(None, ROUTERS_WITH_RULE)
        self.assertEqual(1, self.driver.remove_metering_label_rule.call_count)

    def test_routers_updated(self):
        self.agent.routers_updated(None, ROUTERS)
        self.assertEqual(1, self.driver.update_routers.call_count)

    def test_get_traffic_counters(self):
        self.agent._get_traffic_counters(None, ROUTERS)
        self.assertEqual(1, self.driver.get_traffic_counters.call_count)

    def test_sync_router_namespaces(self):
        self.agent._sync_router_namespaces(None, ROUTERS)
        self.assertEqual(1, self.driver.sync_router_namespaces.call_count)

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

        self.assertEqual('l3.meter', n['event_type'])

        payload = n['payload']
        self.assertEqual(PROJECT_ID, payload['project_id'])
        self.assertEqual(LABEL_ID, payload['label_id'])
        self.assertEqual(88, payload['pkts'])
        self.assertEqual(444, payload['bytes'])

    def test_notification_report_interval(self):
        measure_interval = 30
        report_interval = 600

        now = timeutils.utcnow()
        time_fixture = self.useFixture(utils_fixture.TimeFixture(now))

        self.agent.routers_updated(None, ROUTERS)

        self.driver.get_traffic_counters.return_value = {LABEL_ID:
                                                         {'pkts': 889,
                                                          'bytes': 4440}}

        cfg.CONF.set_override('measure_interval', measure_interval)
        cfg.CONF.set_override('report_interval', report_interval)
        cfg.CONF.set_override('granular_traffic_data', False)

        for i in range(report_interval):
            self.agent._metering_loop()
            count = 0

            if len(fake_notifier.NOTIFICATIONS) > 1:
                for n in fake_notifier.NOTIFICATIONS:
                    if n['event_type'] == 'l3.meter':
                        # skip the first notification because the time is 0
                        count += 1
                        if count > 1:
                            break

            time_fixture.advance_time_seconds(measure_interval)

        self.assertEqual('l3.meter', n['event_type'])

        payload = n['payload']
        self.assertEqual(PROJECT_ID, payload['project_id'])
        self.assertEqual(LABEL_ID, payload['label_id'])
        self.assertLess((payload['time'] - report_interval),
                        measure_interval, payload)
        interval = (payload['last_update'] - payload['first_update']) \
            - report_interval
        self.assertLess(interval, measure_interval, payload)

    def test_router_deleted(self):
        label_id = _uuid()
        self.driver.get_traffic_counters = mock.MagicMock()

        expected_traffic_counters = {'pkts': 44, 'bytes': 222}
        self.driver.get_traffic_counters.return_value = {
            label_id: expected_traffic_counters}

        self.agent._add_metering_info = mock.MagicMock()

        self.agent.routers_updated(None, ROUTERS)
        self.agent.router_deleted(None, ROUTERS[0]['id'])

        self.assertEqual(1, self.agent._add_metering_info.call_count)
        self.assertEqual(1, self.driver.remove_router.call_count)

        self.agent._add_metering_info.assert_called_with(
            label_id, expected_traffic_counters)

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
        actual_info = self.agent._add_metering_info(
            'fake_label_id', expected_info)

        self.assertEqual(1, len(self.agent.metering_infos))
        self.assertEqual(expected_info, actual_info)
        self.assertEqual(expected_info,
                         self.agent.metering_infos['fake_label_id'])
        self.assertEqual(1, mock_time.call_count)

    def test_add_metering_info_create_no_granular_traffic_counters(self):
        expected_info = {'bytes': 1, 'pkts': 1, 'time': 0, 'first_update': 1,
                         'last_update': 1, 'traffic-counter-granularity': None}
        self._test_add_metering_info(expected_info, 1)

    def test_add_metering_info_update(self):
        expected_info = {'bytes': 1, 'pkts': 1, 'time': 0, 'first_update': 1,
                         'last_update': 1}
        self.agent.metering_infos = {'fake_label_id': expected_info}
        expected_info.update({'bytes': 2, 'pkts': 2, 'time': 1,
                              'last_update': 2})
        self._test_add_metering_info(expected_info, 2)

    def test_metering_agent_host_value(self):
        expected_host = 'my agent'
        self.assertEqual(expected_host, self.agent.host)


class TestMeteringDriver(base.BaseTestCase):
    def setUp(self):
        super(TestMeteringDriver, self).setUp()
        metering_agent_config.register_metering_agent_opts()

        cfg.CONF.set_override('driver', 'noop')

        self.agent = metering_agent.MeteringAgent('my agent', cfg.CONF)
        self.driver = mock.Mock()
        self.agent.metering_driver = self.driver

    def test_add_metering_label_with_bad_driver_impl(self):
        del self.driver.add_metering_label

        with mock.patch.object(metering_agent, 'LOG') as log:
            self.agent.add_metering_label(None, ROUTERS)
            log.exception.assert_called_with(mock.ANY,
                                             {'driver': 'noop',
                                              'func': 'add_metering_label'})

    def test_add_metering_label_runtime_error(self):
        self.driver.add_metering_label.side_effect = RuntimeError

        with mock.patch.object(metering_agent, 'LOG') as log:
            self.agent.add_metering_label(None, ROUTERS)
            log.exception.assert_called_with(mock.ANY,
                                             {'driver': 'noop',
                                              'func':
                                              'add_metering_label'})

    def test_init_chain(self):
        with mock.patch('oslo_service.'
                        'periodic_task.PeriodicTasks.__init__') as init:
            metering_agent.MeteringAgent('my agent', cfg.CONF)
        init.assert_called_once_with(cfg.CONF)

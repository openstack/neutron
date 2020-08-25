# Copyright 2012 VMware, Inc.
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

import copy
import functools
from itertools import chain as iter_chain
from itertools import combinations as iter_combinations
import os
import pwd

import eventlet
import fixtures
import mock
import netaddr
from neutron_lib.agent import constants as agent_consts
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as lib_constants
from oslo_config import cfg
from oslo_log import log
import oslo_messaging
from oslo_utils import timeutils
from oslo_utils import uuidutils
from testtools import matchers

from neutron.agent.common import resource_processing_queue
from neutron.agent.common import utils as common_utils
from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3 import dvr_edge_ha_router
from neutron.agent.l3 import dvr_edge_router as dvr_router
from neutron.agent.l3 import dvr_local_router
from neutron.agent.l3 import dvr_router_base
from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import ha_router
from neutron.agent.l3 import legacy_router
from neutron.agent.l3 import link_local_allocator as lla
from neutron.agent.l3 import namespace_manager
from neutron.agent.l3 import namespaces
from neutron.agent.l3 import router_info as l3router
from neutron.agent.linux import dibbler
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.agent.linux import pd
from neutron.agent.linux import ra
from neutron.agent.metadata import driver as metadata_driver
from neutron.agent import rpc as agent_rpc
from neutron.conf.agent import common as agent_config
from neutron.conf.agent.l3 import config as l3_config
from neutron.conf.agent.l3 import ha as ha_conf
from neutron.conf import common as base_config
from neutron.tests import base
from neutron.tests.common import l3_test_common
from neutron.tests.unit.agent.linux.test_utils import FakeUser

_uuid = uuidutils.generate_uuid
HOSTNAME = 'myhost'
FAKE_ID = _uuid()
FAKE_ID_2 = _uuid()
FIP_PRI = 32768


class BasicRouterOperationsFramework(base.BaseTestCase):
    def setUp(self):
        super(BasicRouterOperationsFramework, self).setUp()
        mock.patch('eventlet.spawn').start()
        self.conf = agent_config.setup_conf()
        self.conf.register_opts(base_config.core_opts)
        log.register_options(self.conf)
        self.conf.register_opts(agent_config.AGENT_STATE_OPTS, 'AGENT')
        l3_config.register_l3_agent_config_opts(l3_config.OPTS, self.conf)
        ha_conf.register_l3_agent_ha_opts(self.conf)
        agent_config.register_interface_driver_opts_helper(self.conf)
        agent_config.register_process_monitor_opts(self.conf)
        agent_config.register_availability_zone_opts_helper(self.conf)
        agent_config.register_interface_opts(self.conf)
        agent_config.register_external_process_opts(self.conf)
        agent_config.register_pd_opts(self.conf)
        agent_config.register_ra_opts(self.conf)
        self.conf.set_override('interface_driver',
                               'neutron.agent.linux.interface.NullDriver')
        self.conf.set_override('state_path', cfg.CONF.state_path)
        self.conf.set_override('pd_dhcp_driver', '')

        self.device_exists_p = mock.patch(
            'neutron.agent.linux.ip_lib.device_exists')
        self.device_exists = self.device_exists_p.start()

        self.list_network_namespaces_p = mock.patch(
            'neutron.agent.linux.ip_lib.list_network_namespaces')
        self.list_network_namespaces = self.list_network_namespaces_p.start()

        self.ensure_dir = mock.patch(
            'oslo_utils.fileutils.ensure_tree').start()

        mock.patch('neutron.agent.linux.keepalived.KeepalivedManager'
                   '.get_full_config_file_path').start()

        self.utils_exec_p = mock.patch(
            'neutron.agent.linux.utils.execute')
        self.utils_exec = self.utils_exec_p.start()

        self.utils_replace_file_p = mock.patch(
            'neutron_lib.utils.file.replace_file')
        self.utils_replace_file = self.utils_replace_file_p.start()

        self.external_process_p = mock.patch(
            'neutron.agent.linux.external_process.ProcessManager')
        self.external_process = self.external_process_p.start()
        self.process_monitor = mock.patch(
            'neutron.agent.linux.external_process.ProcessMonitor').start()

        self.send_adv_notif_p = mock.patch(
            'neutron.agent.linux.ip_lib.send_ip_addr_adv_notif')
        self.send_adv_notif = self.send_adv_notif_p.start()

        self.dvr_cls_p = mock.patch('neutron.agent.linux.interface.NullDriver')
        driver_cls = self.dvr_cls_p.start()
        self.mock_driver = mock.MagicMock()
        self.mock_driver.DEV_NAME_LEN = (
            interface.LinuxInterfaceDriver.DEV_NAME_LEN)
        driver_cls.return_value = self.mock_driver

        self.ip_cls_p = mock.patch('neutron.agent.linux.ip_lib.IPWrapper')
        ip_cls = self.ip_cls_p.start()
        self.mock_ip = mock.MagicMock()
        ip_cls.return_value = self.mock_ip

        self.mock_add_ip_rule = mock.patch.object(ip_lib,
                                                  'add_ip_rule').start()
        self.mock_add_ip_rule = mock.patch.object(ip_lib,
                                                  'delete_ip_rule').start()

        ip_dev = mock.patch('neutron.agent.linux.ip_lib.IPDevice').start()
        self.mock_ip_dev = mock.MagicMock()
        ip_dev.return_value = self.mock_ip_dev

        self.l3pluginApi_cls_p = mock.patch(
            'neutron.agent.l3.agent.L3PluginApi')
        l3pluginApi_cls = self.l3pluginApi_cls_p.start()
        self.plugin_api = mock.MagicMock()
        l3pluginApi_cls.return_value = self.plugin_api

        self.looping_call_p = mock.patch(
            'oslo_service.loopingcall.FixedIntervalLoopingCall')
        self.looping_call_p.start()

        subnet_id_1 = _uuid()
        subnet_id_2 = _uuid()
        self.snat_ports = [{'subnets': [{'cidr': '152.2.0.0/16',
                                         'gateway_ip': '152.2.0.1',
                                         'id': subnet_id_1}],
                            'mtu': 1500,
                            'network_id': _uuid(),
                            'device_owner':
                            lib_constants.DEVICE_OWNER_ROUTER_SNAT,
                            'mac_address': 'fa:16:3e:80:8d:80',
                            'fixed_ips': [{'subnet_id': subnet_id_1,
                                           'ip_address': '152.2.0.13',
                                           'prefixlen': 16}],
                            'id': _uuid(), 'device_id': _uuid()},
                           {'subnets': [{'cidr': '152.10.0.0/16',
                                         'gateway_ip': '152.10.0.1',
                                         'id': subnet_id_2}],
                            'mtu': 1450,
                            'network_id': _uuid(),
                            'device_owner':
                            lib_constants.DEVICE_OWNER_ROUTER_SNAT,
                            'mac_address': 'fa:16:3e:80:8d:80',
                            'fixed_ips': [{'subnet_id': subnet_id_2,
                                           'ip_address': '152.10.0.13',
                                           'prefixlen': 16}],
                            'id': _uuid(), 'device_id': _uuid()}]

        self.ri_kwargs = {'agent_conf': self.conf,
                          'interface_driver': self.mock_driver}

    def _process_router_instance_for_agent(self, agent, ri, router):
        ri.router = router
        if not ri.radvd:
            ri.radvd = ra.DaemonMonitor(router['id'],
                                        ri.ns_name,
                                        agent.process_monitor,
                                        ri.get_internal_device_name,
                                        self.conf)
        ri.process()


class IptablesFixture(fixtures.Fixture):
    def _setUp(self):
        # We MUST save and restore random_fully because it is a class
        # attribute and could change state in some tests, which can cause
        # the other router test cases to randomly fail due to race conditions.
        self.random_fully = iptables_manager.IptablesManager.random_fully
        iptables_manager.IptablesManager.random_fully = True
        self.addCleanup(self._reset)

    def _reset(self):
        iptables_manager.IptablesManager.random_fully = self.random_fully


class TestBasicRouterOperations(BasicRouterOperationsFramework):
    def setUp(self):
        super(TestBasicRouterOperations, self).setUp()
        self.useFixture(IptablesFixture())

    def test_request_id_changes(self):
        a = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.assertNotEqual(a.context.request_id, a.context.request_id)
        self.useFixture(IptablesFixture())

    def test_init_ha_conf(self):
        with mock.patch('os.path.dirname', return_value='/etc/ha/'):
            l3_agent.L3NATAgent(HOSTNAME, self.conf)
            self.ensure_dir.assert_called_once_with('/etc/ha/', mode=0o755)

    def test_enqueue_state_change_router_not_found(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        non_existent_router = 42

        # Make sure the exceptional code path has coverage
        agent.enqueue_state_change(non_existent_router, 'master')

    def _enqueue_state_change_transitions(self, transitions, num_called):
        self.conf.set_override('ha_vrrp_advert_int', 1)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent._update_transition_state('router_id')
        with mock.patch.object(agent, '_get_router_info', return_value=None) \
                as mock_get_router_info:
            for state in transitions:
                agent.enqueue_state_change('router_id', state)
                eventlet.sleep(0.2)
            # NOTE(ralonsoh): the wait process should be done inside the mock
            # context, to allow the spawned thread to call the mocked function
            # before the context ends.
            eventlet.sleep(self.conf.ha_vrrp_advert_int + 2)

        if num_called:
            mock_get_router_info.assert_has_calls(
                [mock.call('router_id') for _ in range(num_called)])
        else:
            mock_get_router_info.assert_not_called()

    def test_enqueue_state_change_from_none_to_master(self):
        self._enqueue_state_change_transitions(['master'], 1)

    def test_enqueue_state_change_from_none_to_backup(self):
        self._enqueue_state_change_transitions(['backup'], 1)

    def test_enqueue_state_change_from_none_to_master_to_backup(self):
        self._enqueue_state_change_transitions(['master', 'backup'], 0)

    def test_enqueue_state_change_from_none_to_backup_to_master(self):
        self._enqueue_state_change_transitions(['backup', 'master'], 2)

    def test_enqueue_state_change_metadata_disable(self):
        self.conf.set_override('enable_metadata_proxy', False)
        self.conf.set_override('ha_vrrp_advert_int', 1)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = mock.Mock()
        router_info = mock.MagicMock()
        agent.router_info[router.id] = router_info
        agent._update_metadata_proxy = mock.Mock()
        agent.enqueue_state_change(router.id, 'master')
        eventlet.sleep(self.conf.ha_vrrp_advert_int + 2)
        self.assertFalse(agent._update_metadata_proxy.call_count)

    def test_enqueue_state_change_l3_extension(self):
        self.conf.set_override('ha_vrrp_advert_int', 1)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = mock.Mock()
        router_info = mock.MagicMock()
        router_info.agent = agent
        agent.router_info[router.id] = router_info
        agent.l3_ext_manager.ha_state_change = mock.Mock()
        agent.enqueue_state_change(router.id, 'master')
        eventlet.sleep(self.conf.ha_vrrp_advert_int + 2)
        agent.l3_ext_manager.ha_state_change.assert_called_once_with(
            agent.context,
            {'router_id': router.id, 'state': 'master',
             'host': agent.host})

    def test_enqueue_state_change_router_active_ha(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = {'distributed': False}
        router_info = mock.MagicMock(router=router)
        with mock.patch.object(
            agent.metadata_driver, 'spawn_monitored_metadata_proxy'
        ) as spawn_metadata_proxy, mock.patch.object(
            agent.metadata_driver, 'destroy_monitored_metadata_proxy'
        ) as destroy_metadata_proxy:
            agent._update_metadata_proxy(router_info, "router_id", "master")
        spawn_metadata_proxy.assert_called()
        destroy_metadata_proxy.assert_not_called()

    def test_enqueue_state_change_router_standby_ha(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = {'distributed': False}
        router_info = mock.MagicMock(router=router)
        with mock.patch.object(
            agent.metadata_driver, 'spawn_monitored_metadata_proxy'
        ) as spawn_metadata_proxy, mock.patch.object(
            agent.metadata_driver, 'destroy_monitored_metadata_proxy'
        ) as destroy_metadata_proxy:
            agent._update_metadata_proxy(router_info, "router_id", "standby")
        spawn_metadata_proxy.assert_not_called()
        destroy_metadata_proxy.assert_called()

    def test_enqueue_state_change_router_standby_ha_dvr(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = {'distributed': True}
        router_info = mock.MagicMock(router=router)
        with mock.patch.object(
            agent.metadata_driver, 'spawn_monitored_metadata_proxy'
        ) as spawn_metadata_proxy, mock.patch.object(
            agent.metadata_driver, 'destroy_monitored_metadata_proxy'
        ) as destroy_metadata_proxy:
            agent._update_metadata_proxy(router_info, "router_id", "standby")
        spawn_metadata_proxy.assert_called()
        destroy_metadata_proxy.assert_not_called()

    def _test__configure_ipv6_params_helper(self, state, gw_port_id):
        with mock.patch(
                'neutron.common.ipv6_utils.is_enabled_and_bind_by_default',
                return_value=True):
            agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        router_info = l3router.RouterInfo(agent, _uuid(), {}, **self.ri_kwargs)
        if gw_port_id:
            router_info.ex_gw_port = {'id': gw_port_id}
        expected_forwarding_state = state == 'master'
        with mock.patch.object(
            router_info.driver, "configure_ipv6_forwarding"
        ) as configure_ipv6_forwarding, mock.patch.object(
            router_info, "_configure_ipv6_params_on_gw"
        ) as configure_ipv6_on_gw:
            agent._configure_ipv6_params(router_info, state)

            if state == 'master':
                configure_ipv6_forwarding.assert_called_once_with(
                    router_info.ns_name, 'all', expected_forwarding_state)
            else:
                configure_ipv6_forwarding.assert_not_called()

            if gw_port_id:
                interface_name = router_info.get_external_device_name(
                        router_info.ex_gw_port['id'])
                configure_ipv6_on_gw.assert_called_once_with(
                    router_info.ex_gw_port, router_info.ns_name,
                    interface_name, expected_forwarding_state)
            else:
                configure_ipv6_on_gw.assert_not_called()

    def test__configure_ipv6_params_master(self):
        self._test__configure_ipv6_params_helper('master', gw_port_id=_uuid())

    def test__configure_ipv6_params_backup(self):
        self._test__configure_ipv6_params_helper('backup', gw_port_id=_uuid())

    def test__configure_ipv6_params_master_no_gw_port(self):
        self._test__configure_ipv6_params_helper('master', gw_port_id=None)

    def test__configure_ipv6_params_backup_no_gw_port(self):
        self._test__configure_ipv6_params_helper('backup', gw_port_id=None)

    def test_check_ha_state_for_router_master_standby(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = mock.Mock()
        router.id = '1234'
        router_info = mock.MagicMock()
        agent.router_info[router.id] = router_info
        router_info.ha_state = 'master'
        with mock.patch.object(agent.state_change_notifier,
                               'queue_event') as queue_event:
            agent.check_ha_state_for_router(
                router.id, lib_constants.HA_ROUTER_STATE_STANDBY)
            queue_event.assert_called_once_with((router.id, 'master'))

    def test_check_ha_state_for_router_standby_standby(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = mock.Mock()
        router.id = '1234'
        router_info = mock.MagicMock()
        agent.router_info[router.id] = router_info
        router_info.ha_state = 'backup'
        with mock.patch.object(agent.state_change_notifier,
                               'queue_event') as queue_event:
            agent.check_ha_state_for_router(
                router.id, lib_constants.HA_ROUTER_STATE_STANDBY)
            queue_event.assert_not_called()

    def test_periodic_sync_routers_task_raise_exception(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.plugin_api.get_router_ids.return_value = ['fake_id']
        self.plugin_api.get_routers.side_effect = ValueError
        self.assertRaises(ValueError,
                          agent.periodic_sync_routers_task,
                          agent.context)
        self.assertTrue(agent.fullsync)

    def test_l3_initial_report_state_done(self):
        with mock.patch.object(l3_agent.L3NATAgentWithStateReport,
                               'periodic_sync_routers_task'),\
                mock.patch.object(agent_rpc.PluginReportStateAPI,
                                  'report_state') as report_state,\
                mock.patch.object(eventlet, 'spawn_n'):

            agent = l3_agent.L3NATAgentWithStateReport(host=HOSTNAME,
                                                       conf=self.conf)

            self.assertTrue(agent.agent_state['start_flag'])
            agent.after_start()
            report_state.assert_called_once_with(agent.context,
                                                 agent.agent_state,
                                                 True)
            self.assertIsNone(agent.agent_state.get('start_flag'))

    def test_report_state_revival_logic(self):
        with mock.patch.object(agent_rpc.PluginReportStateAPI,
                               'report_state') as report_state:
            agent = l3_agent.L3NATAgentWithStateReport(host=HOSTNAME,
                                                       conf=self.conf)
            report_state.return_value = agent_consts.AGENT_REVIVED
            agent._report_state()
            self.assertTrue(agent.fullsync)

            agent.fullsync = False
            report_state.return_value = agent_consts.AGENT_ALIVE
            agent._report_state()
            self.assertFalse(agent.fullsync)

    def test_periodic_sync_routers_task_call_clean_stale_namespaces(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.plugin_api.get_routers.return_value = []
        agent.periodic_sync_routers_task(agent.context)
        self.assertFalse(agent.namespaces_manager._clean_stale)

    def test_periodic_sync_routers_task_call_ensure_snat_cleanup(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.conf.agent_mode = 'dvr_snat'
        dvr_ha_router = {'id': _uuid(),
                         'external_gateway_info': {},
                         'routes': [],
                         'distributed': True,
                         'ha': True}
        dvr_router = {'id': _uuid(),
                      'external_gateway_info': {},
                      'routes': [],
                      'distributed': True,
                      'ha': False}
        routers = [dvr_router, dvr_ha_router]
        self.plugin_api.get_router_ids.return_value = [r['id'] for r
                                                       in routers]
        self.plugin_api.get_routers.return_value = routers
        with mock.patch.object(namespace_manager.NamespaceManager,
                               'ensure_snat_cleanup') as ensure_snat_cleanup:
            agent.periodic_sync_routers_task(agent.context)
            ensure_snat_cleanup.assert_called_once_with(dvr_router['id'])

    def test_periodic_sync_routers_task_call_clean_stale_meta_proxies(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        stale_router_ids = [_uuid(), _uuid()]
        active_routers = [{'id': _uuid()}, {'id': _uuid()}]
        self.plugin_api.get_router_ids.return_value = [r['id'] for r
                                                       in active_routers]
        self.plugin_api.get_routers.return_value = active_routers
        namespace_list = [namespaces.NS_PREFIX + r_id
                          for r_id in stale_router_ids]
        namespace_list += [namespaces.NS_PREFIX + r['id']
                           for r in active_routers]
        self.list_network_namespaces.return_value = namespace_list
        driver = metadata_driver.MetadataDriver
        with mock.patch.object(
                driver, 'destroy_monitored_metadata_proxy') as destroy_proxy:
            agent.periodic_sync_routers_task(agent.context)

            expected_calls = [
                mock.call(
                    mock.ANY, r_id, agent.conf, namespaces.NS_PREFIX + r_id)
                for r_id in stale_router_ids]
            self.assertEqual(len(stale_router_ids), destroy_proxy.call_count)
            destroy_proxy.assert_has_calls(expected_calls, any_order=True)

    def test__create_router_legacy_agent(self):
        router = {'distributed': False, 'ha': False}

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router_info = agent._create_router(_uuid(), router)

        self.assertEqual(legacy_router.LegacyRouter, type(router_info))

    def test__create_router_ha_agent(self):
        router = {'distributed': False, 'ha': True}

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router_info = agent._create_router(_uuid(), router)

        self.assertEqual(ha_router.HaRouter, type(router_info))

    def test__create_router_dvr_agent(self):
        router = {'distributed': True, 'ha': False}

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router_info = agent._create_router(_uuid(), router)

        self.assertEqual(dvr_local_router.DvrLocalRouter, type(router_info))

    def test__create_router_dvr_agent_with_dvr_snat_mode(self):
        router = {'distributed': True, 'ha': False}

        self.conf.set_override('agent_mode',
                               lib_constants.L3_AGENT_MODE_DVR_SNAT)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router_info = agent._create_router(_uuid(), router)

        self.assertEqual(dvr_router.DvrEdgeRouter, type(router_info))

    def test__create_router_dvr_ha_agent(self):
        router = {'distributed': True, 'ha': True}

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router_info = agent._create_router(_uuid(), router)

        self.assertEqual(dvr_local_router.DvrLocalRouter, type(router_info))

    def test__create_router_dvr_ha_agent_with_dvr_snat_mode(self):
        router = {'distributed': True, 'ha': True,
                  lib_constants.HA_INTERFACE_KEY: None}

        self.conf.set_override('agent_mode',
                               lib_constants.L3_AGENT_MODE_DVR_SNAT)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router_info = agent._create_router(_uuid(), router)

        self.assertEqual(dvr_router.DvrEdgeRouter, type(router_info))

        router = {'distributed': True, 'ha': True,
                  lib_constants.HA_INTERFACE_KEY: True}

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router_info = agent._create_router(_uuid(), router)

        self.assertEqual(dvr_edge_ha_router.DvrEdgeHaRouter, type(router_info))

    def test_router_info_create(self):
        id = _uuid()
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = l3router.RouterInfo(agent, id, {}, **self.ri_kwargs)

        self.assertTrue(ri.ns_name.endswith(id))

    def test_router_info_create_with_router(self):
        ns_id = _uuid()
        subnet_id = _uuid()
        ex_gw_port = {'id': _uuid(),
                      'network_id': _uuid(),
                      'fixed_ips': [{'ip_address': '19.4.4.4',
                                     'prefixlen': 24,
                                     'subnet_id': subnet_id}],
                      'subnets': [{'id': subnet_id,
                                   'cidr': '19.4.4.0/24',
                                   'gateway_ip': '19.4.4.1'}]}
        router = {
            'id': _uuid(),
            'enable_snat': True,
            'routes': [],
            'gw_port': ex_gw_port}
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = l3router.RouterInfo(agent, ns_id, router, **self.ri_kwargs)
        self.assertTrue(ri.ns_name.endswith(ns_id))
        self.assertEqual(router, ri.router)

    def test_agent_create(self):
        l3_agent.L3NATAgent(HOSTNAME, self.conf)

    def _test_internal_network_action(self, action):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router_id = router['id']
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = l3router.RouterInfo(agent, router_id,
                                 router, **self.ri_kwargs)
        port = {'network_id': _uuid(),
                'id': _uuid(),
                'mac_address': 'ca:fe:de:ad:be:ef',
                'mtu': 1500,
                'fixed_ips': [{'subnet_id': _uuid(),
                               'ip_address': '99.0.1.9',
                               'prefixlen': 24}]}

        interface_name = ri.get_internal_device_name(port['id'])

        if action == 'add':
            self.device_exists.return_value = False
            ri.internal_network_added(port)
            self.assertEqual(1, self.mock_driver.plug.call_count)
            self.assertEqual(1, self.mock_driver.init_router_port.call_count)
            self.send_adv_notif.assert_called_once_with(ri.ns_name,
                                                        interface_name,
                                                        '99.0.1.9')
        elif action == 'remove':
            self.device_exists.return_value = True
            ri.internal_network_removed(port)
            self.assertEqual(1, self.mock_driver.unplug.call_count)
        else:
            raise Exception("Invalid action %s" % action)

    @staticmethod
    def _fixed_ip_cidr(fixed_ip):
        return '%s/%s' % (fixed_ip['ip_address'], fixed_ip['prefixlen'])

    def _test_internal_network_action_dist(self, action, scope_match=False):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        subnet_id = _uuid()
        port = {'network_id': _uuid(),
                'id': _uuid(),
                'mac_address': 'ca:fe:de:ad:be:ef',
                'mtu': 1500,
                'fixed_ips': [{'subnet_id': subnet_id,
                               'ip_address': '99.0.1.9',
                               'prefixlen': 24}],
                'subnets': [{'id': subnet_id}]}

        ri.router['gw_port_host'] = HOSTNAME
        agent.host = HOSTNAME
        agent.conf.agent_mode = 'dvr_snat'
        sn_port = {'fixed_ips': [{'ip_address': '20.0.0.31',
                                  'subnet_id': _uuid()}],
                   'subnets': [{'gateway_ip': '20.0.0.1'}],
                   'extra_subnets': [{'cidr': '172.16.0.0/24'}],
                   'id': _uuid(),
                   'network_id': _uuid(),
                   'mtu': 1500,
                   'mac_address': 'ca:fe:de:ad:be:ef'}
        ex_gw_port = {'fixed_ips': [{'ip_address': '20.0.0.30',
                                     'prefixlen': 24,
                                     'subnet_id': _uuid()}],
                      'subnets': [{'gateway_ip': '20.0.0.1'}],
                      'extra_subnets': [{'cidr': '172.16.0.0/24'}],
                      'id': _uuid(),
                      portbindings.HOST_ID: HOSTNAME,
                      'network_id': _uuid(),
                      'mtu': 1500,
                      'mac_address': 'ca:fe:de:ad:be:ef'}
        ri.snat_ports = sn_port
        ri.ex_gw_port = ex_gw_port
        ri.snat_namespace = mock.Mock()
        if scope_match:
            ri._check_if_address_scopes_match = mock.Mock(return_value=True)
        else:
            ri._check_if_address_scopes_match = mock.Mock(return_value=False)
        if action == 'add':
            self.device_exists.return_value = False

            ri.get_snat_port_for_internal_port = mock.Mock(
                return_value=sn_port)
            ri._snat_redirect_add = mock.Mock()
            ri._set_subnet_arp_info = mock.Mock()
            ri._internal_network_added = mock.Mock()
            ri._set_subnet_arp_info = mock.Mock()
            ri._port_has_ipv6_subnet = mock.Mock(return_value=False)
            ri._add_interface_routing_rule_to_router_ns = mock.Mock()
            ri._add_interface_route_to_fip_ns = mock.Mock()
            ri.internal_network_added(port)
            self.assertEqual(2, ri._internal_network_added.call_count)
            ri._set_subnet_arp_info.assert_called_once_with(subnet_id)
            ri._internal_network_added.assert_called_with(
                dvr_snat_ns.SnatNamespace.get_snat_ns_name(ri.router['id']),
                sn_port['network_id'],
                sn_port['id'],
                sn_port['fixed_ips'],
                sn_port['mac_address'],
                ri._get_snat_int_device_name(sn_port['id']),
                lib_constants.SNAT_INT_DEV_PREFIX,
                mtu=1500)
            self.assertTrue(ri._check_if_address_scopes_match.called)
            if scope_match:
                self.assertTrue(
                    ri._add_interface_routing_rule_to_router_ns.called)
                self.assertTrue(
                    ri._add_interface_route_to_fip_ns.called)
                self.assertEqual(0, ri._snat_redirect_add.call_count)
            else:
                self.assertFalse(
                    ri._add_interface_routing_rule_to_router_ns.called)
                self.assertFalse(
                    ri._add_interface_route_to_fip_ns.called)
                self.assertEqual(1, ri._snat_redirect_add.call_count)
        elif action == 'remove':
            self.device_exists.return_value = False
            ri.get_snat_port_for_internal_port = mock.Mock(
                return_value=sn_port)
            ri._delete_arp_cache_for_internal_port = mock.Mock()
            ri._snat_redirect_modify = mock.Mock()
            ri._port_has_ipv6_subnet = mock.Mock(return_value=False)
            ri._delete_interface_routing_rule_in_router_ns = mock.Mock()
            ri._delete_interface_route_in_fip_ns = mock.Mock()
            ri.internal_network_removed(port)
            self.assertEqual(
                1, ri._delete_arp_cache_for_internal_port.call_count)
            self.assertTrue(ri._check_if_address_scopes_match.called)
            if scope_match:
                self.assertFalse(ri._snat_redirect_modify.called)
                self.assertTrue(
                    ri._delete_interface_routing_rule_in_router_ns.called)
                self.assertTrue(
                    ri._delete_interface_route_in_fip_ns.called)
            else:
                ri._snat_redirect_modify.assert_called_with(
                    sn_port, port,
                    ri.get_internal_device_name(port['id']),
                    is_add=False)
                self.assertFalse(
                    ri._delete_interface_routing_rule_in_router_ns.called)
                self.assertFalse(
                    ri._delete_interface_route_in_fip_ns.called)

    def test_agent_add_internal_network(self):
        self._test_internal_network_action('add')

    def test_agent_add_internal_network_dist(self):
        self._test_internal_network_action_dist('add')

    def test_agent_add_internal_network_dist_with_addr_scope_match(self):
        self._test_internal_network_action_dist('add', scope_match=True)

    def test_agent_remove_internal_network(self):
        self._test_internal_network_action('remove')

    def test_agent_remove_internal_network_dist_with_addr_scope_mismatch(self):
        self._test_internal_network_action_dist('remove', scope_match=True)

    def test_agent_remove_internal_network_dist(self):
        self._test_internal_network_action_dist('remove')

    def _add_external_gateway(self, ri, router, ex_gw_port, interface_name,
                              use_fake_fip=False,
                              no_subnet=False, no_sub_gw=None,
                              dual_stack=False):
        self.device_exists.return_value = False
        if no_sub_gw is None:
            no_sub_gw = []
        if use_fake_fip:
            fake_fip = {'floatingips': [{'id': _uuid(),
                                         'floating_ip_address': '192.168.1.34',
                                         'fixed_ip_address': '192.168.0.1',
                                         'port_id': _uuid()}]}
            router[lib_constants.FLOATINGIP_KEY] = fake_fip['floatingips']
        ri.external_gateway_added(ex_gw_port, interface_name)
        if not router.get('distributed'):
            self.assertEqual(1, self.mock_driver.plug.call_count)
            self.assertEqual(1, self.mock_driver.init_router_port.call_count)
            if no_subnet and not dual_stack:
                self.assertEqual(0, self.send_adv_notif.call_count)
                ip_cidrs = []
                kwargs = {'preserve_ips': [],
                          'namespace': 'qrouter-' + router['id'],
                          'extra_subnets': [],
                          'clean_connections': True}
            else:
                exp_arp_calls = [mock.call(ri.ns_name, interface_name,
                                           '20.0.0.30')]
                if dual_stack and not no_sub_gw:
                    exp_arp_calls += [mock.call(ri.ns_name, interface_name,
                                                '2001:192:168:100::2')]
                self.send_adv_notif.assert_has_calls(exp_arp_calls)
                ip_cidrs = ['20.0.0.30/24']
                if dual_stack:
                    if not no_sub_gw:
                        ip_cidrs.append('2001:192:168:100::2/64')
                kwargs = {'preserve_ips': ['192.168.1.34/32'],
                          'namespace': 'qrouter-' + router['id'],
                          'extra_subnets': [{'cidr': '172.16.0.0/24'}],
                          'clean_connections': True}
            self.mock_driver.init_router_port.assert_called_with(
                interface_name, ip_cidrs, **kwargs)
        else:
            ri._create_dvr_gateway.assert_called_once_with(
                ex_gw_port, interface_name)

    def _set_ri_kwargs(self, agent, router_id, router):
        self.ri_kwargs['agent'] = agent
        self.ri_kwargs['router_id'] = router_id
        self.ri_kwargs['router'] = router

    def _test_external_gateway_action(self, action, router, dual_stack=False):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ex_net_id = _uuid()
        sn_port = self.snat_ports[1]
        # Special setup for dvr routers
        if router.get('distributed'):
            agent.conf.agent_mode = 'dvr_snat'
            agent.host = HOSTNAME
            self._set_ri_kwargs(agent, router['id'], router)
            ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
            ri._create_dvr_gateway = mock.Mock()
            ri.get_snat_interfaces = mock.Mock(return_value=self.snat_ports)
            ri.snat_ports = self.snat_ports
            ri._create_snat_namespace()
            ri.fip_ns = agent.get_fip_ns(ex_net_id)
            ri.internal_ports = self.snat_ports
        else:
            ri = l3router.RouterInfo(
                agent, router['id'], router,
                **self.ri_kwargs)

        ri.use_ipv6 = False
        subnet_id = _uuid()
        fixed_ips = [{'subnet_id': subnet_id,
                      'ip_address': '20.0.0.30',
                      'prefixlen': 24}]
        subnets = [{'id': subnet_id,
                    'cidr': '20.0.0.0/24',
                    'gateway_ip': '20.0.0.1'}]
        if dual_stack:
            ri.use_ipv6 = True
            subnet_id_v6 = _uuid()
            fixed_ips.append({'subnet_id': subnet_id_v6,
                              'ip_address': '2001:192:168:100::2',
                              'prefixlen': 64})
            subnets.append({'id': subnet_id_v6,
                            'cidr': '2001:192:168:100::/64',
                            'gateway_ip': '2001:192:168:100::1'})
        ex_gw_port = {'fixed_ips': fixed_ips,
                      'subnets': subnets,
                      'extra_subnets': [{'cidr': '172.16.0.0/24'}],
                      'id': _uuid(),
                      'network_id': ex_net_id,
                      'mtu': 1500,
                      'mac_address': 'ca:fe:de:ad:be:ef'}
        ex_gw_port_no_sub = {'fixed_ips': [],
                             'id': _uuid(),
                             'network_id': ex_net_id,
                             'mtu': 1500,
                             'mac_address': 'ca:fe:de:ad:be:ef'}
        interface_name = ri.get_external_device_name(ex_gw_port['id'])

        if action == 'add':
            self._add_external_gateway(ri, router, ex_gw_port, interface_name,
                                       use_fake_fip=True,
                                       dual_stack=dual_stack)

        elif action == 'add_no_sub':
            ri.use_ipv6 = True
            self._add_external_gateway(ri, router, ex_gw_port_no_sub,
                                       interface_name,
                                       no_subnet=True)

        elif action == 'add_no_sub_v6_gw':
            ri.use_ipv6 = True
            self.conf.set_override('ipv6_gateway',
                                   'fe80::f816:3eff:fe2e:1')
            if dual_stack:
                use_fake_fip = True
                # Remove v6 entries
                del ex_gw_port['fixed_ips'][-1]
                del ex_gw_port['subnets'][-1]
            else:
                use_fake_fip = False
                ex_gw_port = ex_gw_port_no_sub
            self._add_external_gateway(ri, router, ex_gw_port,
                                       interface_name, no_subnet=True,
                                       no_sub_gw='fe80::f816:3eff:fe2e:1',
                                       use_fake_fip=use_fake_fip,
                                       dual_stack=dual_stack)

        elif action == 'remove':
            self.device_exists.return_value = True
            ri.get_snat_port_for_internal_port = mock.Mock(
                return_value=sn_port)
            ri._snat_redirect_remove = mock.Mock()
            if router.get('distributed'):
                ri.snat_iptables_manager = iptables_manager.IptablesManager(
                    namespace=ri.snat_namespace.name, use_ipv6=ri.use_ipv6)
                ri.fip_ns.delete_rtr_2_fip_link = mock.Mock()
            ri.router['gw_port'] = ""
            ri.external_gateway_removed(ex_gw_port, interface_name)
            if not router.get('distributed'):
                self.mock_driver.unplug.assert_called_once_with(
                    interface_name,
                    namespace=mock.ANY,
                    prefix=mock.ANY)
            else:
                ri._snat_redirect_remove.assert_called_with(
                    sn_port, sn_port,
                    ri.get_internal_device_name(sn_port['id']))
                ri.get_snat_port_for_internal_port.assert_called_with(
                    mock.ANY, ri.snat_ports)
                self.assertTrue(ri.fip_ns.delete_rtr_2_fip_link.called)
        else:
            raise Exception("Invalid action %s" % action)

    def _test_external_gateway_updated(self, dual_stack=False):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        ri = l3router.RouterInfo(agent, router['id'],
                                 router, **self.ri_kwargs)
        ri.use_ipv6 = False
        interface_name, ex_gw_port = l3_test_common.prepare_ext_gw_test(
            self, ri, dual_stack=dual_stack)

        fake_fip = {'floatingips': [{'id': _uuid(),
                                     'floating_ip_address': '192.168.1.34',
                                     'fixed_ip_address': '192.168.0.1',
                                     'port_id': _uuid()}]}
        router[lib_constants.FLOATINGIP_KEY] = fake_fip['floatingips']
        ri.external_gateway_updated(ex_gw_port, interface_name)
        self.assertEqual(1, self.mock_driver.plug.call_count)
        self.assertEqual(1, self.mock_driver.init_router_port.call_count)
        exp_arp_calls = [mock.call(ri.ns_name, interface_name,
                                   '20.0.0.30')]
        if dual_stack:
            ri.use_ipv6 = True
            exp_arp_calls += [mock.call(ri.ns_name, interface_name,
                                        '2001:192:168:100::2')]
        self.send_adv_notif.assert_has_calls(exp_arp_calls)
        ip_cidrs = ['20.0.0.30/24']
        gateway_ips = ['20.0.0.1']
        if dual_stack:
            ip_cidrs.append('2001:192:168:100::2/64')
            gateway_ips.append('2001:192:168:100::1')
        kwargs = {'preserve_ips': ['192.168.1.34/32'],
                  'namespace': 'qrouter-' + router['id'],
                  'extra_subnets': [{'cidr': '172.16.0.0/24'}],
                  'clean_connections': True}
        self.mock_driver.init_router_port.assert_called_with(interface_name,
                                                             ip_cidrs,
                                                             **kwargs)

    def test_external_gateway_updated(self):
        self._test_external_gateway_updated()

    def test_external_gateway_updated_dual_stack(self):
        self._test_external_gateway_updated(dual_stack=True)

    def test_external_gateway_updated_dvr(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.conf.agent_mode = 'dvr_snat'
        agent.host = HOSTNAME
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['distributed'] = True
        router['gw_port_host'] = HOSTNAME
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        ri._create_dvr_gateway = mock.Mock()
        ri.get_snat_interfaces = mock.Mock(return_value=self.snat_ports)
        ri.snat_ports = self.snat_ports
        ri._create_snat_namespace()
        ex_net_id = _uuid()
        ri.fip_ns = agent.get_fip_ns(ex_net_id)
        ri.internal_ports = self.snat_ports
        ri.use_ipv6 = False
        interface_name, ex_gw_port = l3_test_common.prepare_ext_gw_test(
            self, ri)

        fake_fip = {'floatingips': [{'id': _uuid(),
                                     'floating_ip_address': '192.168.1.34',
                                     'fixed_ip_address': '192.168.0.1',
                                     'port_id': _uuid(),
                                     'dvr_snat_bound': True}]}
        router[lib_constants.FLOATINGIP_KEY] = fake_fip['floatingips']
        ri.external_gateway_updated(ex_gw_port, interface_name)
        self.assertEqual(1, self.mock_driver.plug.call_count)
        self.assertEqual(1, self.mock_driver.init_router_port.call_count)
        exp_arp_calls = [mock.call(ri.snat_namespace.name, interface_name,
                                   '20.0.0.30')]
        self.send_adv_notif.assert_has_calls(exp_arp_calls)
        ip_cidrs = ['20.0.0.30/24']
        kwargs = {'preserve_ips': ['192.168.1.34/32'],
                  'namespace': ri.snat_namespace.name,
                  'extra_subnets': [{'cidr': '172.16.0.0/24'}],
                  'clean_connections': True}
        self.mock_driver.init_router_port.assert_called_with(interface_name,
                                                             ip_cidrs,
                                                             **kwargs)

    def test_dvr_edge_router_init_for_snat_namespace_object(self):
        router = {'id': _uuid()}
        self._set_ri_kwargs(mock.Mock(), router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        # Make sure that ri.snat_namespace object is created when the
        # router is initialized, and that it's name matches the gw
        # namespace name
        self.assertIsNotNone(ri.snat_namespace)
        self.assertEqual(ri.snat_namespace.name, ri.get_gw_ns_name())

    def test_ext_gw_updated_calling_snat_ns_delete_if_gw_port_host_none(self):
        """Test to check the impact of snat_namespace object.

        This function specifically checks the impact of the snat
        namespace object value on external_gateway_removed for deleting
        snat_namespace when the gw_port_host mismatches or none.
        """
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        self._set_ri_kwargs(mock.Mock(), router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        with mock.patch.object(dvr_snat_ns.SnatNamespace,
                               'delete') as snat_ns_delete:
            interface_name, ex_gw_port = l3_test_common.prepare_ext_gw_test(
                self, ri)
            router['gw_port_host'] = ''
            ri._snat_redirect_remove = mock.Mock()
            ri.external_gateway_updated(ex_gw_port, interface_name)
            if router['gw_port_host'] != ri.host:
                self.assertFalse(ri._snat_redirect_remove.called)
                self.assertEqual(1, snat_ns_delete.call_count)

    @mock.patch.object(namespaces.Namespace, 'delete')
    def test_snat_ns_delete_not_called_when_snat_namespace_does_not_exist(
            self, mock_ns_del):
        """Test to check the impact of snat_namespace object.

        This function specifically checks the impact of the snat
        namespace object initialization without the actual creation
        of snat_namespace. When deletes are issued to the snat
        namespace based on the snat namespace object existence, it
        should be checking for the valid namespace existence before
        it tries to delete.
        """
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        self._set_ri_kwargs(mock.Mock(), router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        # Make sure we set a return value to emulate the non existence
        # of the namespace.
        self.mock_ip.netns.exists.return_value = False
        self.assertIsNotNone(ri.snat_namespace)
        interface_name, ex_gw_port = l3_test_common.prepare_ext_gw_test(self,
                                                                        ri)
        ri._external_gateway_removed = mock.Mock()
        ri.external_gateway_removed(ex_gw_port, interface_name)
        self.assertFalse(mock_ns_del.called)

    def _test_ext_gw_updated_dvr_edge_router(self, host_match,
                                             snat_hosted_before=True):
        """Helper to test external gw update for edge router on dvr_snat agent

        :param host_match: True if new gw host should be the same as agent host
        :param snat_hosted_before: True if agent has already been hosting
        snat for the router
        """
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        self._set_ri_kwargs(mock.Mock(), router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        if snat_hosted_before:
            ri._create_snat_namespace()
            snat_ns_name = ri.snat_namespace.name

        interface_name, ex_gw_port = l3_test_common.prepare_ext_gw_test(self,
                                                                        ri)
        ri._external_gateway_added = mock.Mock()

        router['gw_port_host'] = ri.host if host_match else (ri.host + 'foo')

        ri.external_gateway_updated(ex_gw_port, interface_name)
        if not host_match:
            self.assertFalse(ri._external_gateway_added.called)
            if snat_hosted_before:
                # host mismatch means that snat was rescheduled to another
                # agent, hence need to verify that gw port was unplugged and
                # snat namespace was deleted
                self.mock_driver.unplug.assert_called_with(
                    interface_name,
                    namespace=snat_ns_name,
                    prefix=namespaces.EXTERNAL_DEV_PREFIX)
        else:
            if not snat_hosted_before:
                self.assertIsNotNone(ri.snat_namespace)
            self.assertTrue(ri._external_gateway_added.called)

    def test_ext_gw_updated_dvr_edge_router(self):
        self._test_ext_gw_updated_dvr_edge_router(host_match=True)

    def test_ext_gw_updated_dvr_edge_router_host_mismatch(self):
        self._test_ext_gw_updated_dvr_edge_router(host_match=False)

    def test_ext_gw_updated_dvr_edge_router_snat_rescheduled(self):
        self._test_ext_gw_updated_dvr_edge_router(host_match=True,
                                                  snat_hosted_before=False)

    def test_agent_add_external_gateway(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        self._test_external_gateway_action('add', router)

    def test_agent_add_external_gateway_dual_stack(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        self._test_external_gateway_action('add', router, dual_stack=True)

    def test_agent_add_external_gateway_dist(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['distributed'] = True
        router['gw_port_host'] = HOSTNAME
        self._test_external_gateway_action('add', router)

    def test_agent_add_external_gateway_dist_dual_stack(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['distributed'] = True
        router['gw_port_host'] = HOSTNAME
        self._test_external_gateway_action('add', router, dual_stack=True)

    def test_agent_add_external_gateway_no_subnet(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2,
                                                    v6_ext_gw_with_sub=False)
        self._test_external_gateway_action('add_no_sub', router)

    def test_agent_add_external_gateway_no_subnet_with_ipv6_gw(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2,
                                                    v6_ext_gw_with_sub=False)
        self._test_external_gateway_action('add_no_sub_v6_gw', router)

    def test_agent_add_external_gateway_dual_stack_no_subnet_w_ipv6_gw(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2,
                                                    v6_ext_gw_with_sub=False)
        self._test_external_gateway_action('add_no_sub_v6_gw',
                                           router, dual_stack=True)

    def test_agent_remove_external_gateway(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        self._test_external_gateway_action('remove', router)

    def test_agent_remove_external_gateway_dual_stack(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        self._test_external_gateway_action('remove', router, dual_stack=True)

    def test_agent_remove_external_gateway_dist(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['distributed'] = True
        router['gw_port_host'] = HOSTNAME
        self._test_external_gateway_action('remove', router)

    def test_agent_remove_external_gateway_dist_dual_stack(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['distributed'] = True
        router['gw_port_host'] = HOSTNAME
        self._test_external_gateway_action('remove', router, dual_stack=True)

    def _verify_snat_mangle_rules(self, nat_rules, mangle_rules, router,
                                  random_fully, negate=False):
        interfaces = router[lib_constants.INTERFACE_KEY]
        source_cidrs = []
        for iface in interfaces:
            for subnet in iface['subnets']:
                prefix = subnet['cidr'].split('/')[1]
                source_cidr = "%s/%s" % (iface['fixed_ips'][0]['ip_address'],
                                         prefix)
                source_cidrs.append(source_cidr)
        source_nat_ip = router['gw_port']['fixed_ips'][0]['ip_address']
        interface_name = ('qg-%s' % router['gw_port']['id'])[:14]
        mask_rule = ('-m mark ! --mark 0x2/%s -m conntrack --ctstate DNAT '
                     '-j SNAT --to-source %s' %
                     (lib_constants.ROUTER_MARK_MASK, source_nat_ip))
        snat_rule = ('-o %s -j SNAT --to-source %s' %
                     (interface_name, source_nat_ip))
        if random_fully:
            mask_rule += ' --random-fully'
            snat_rule += ' --random-fully'
        expected_rules = [
            '! -i %s ! -o %s -m conntrack ! --ctstate DNAT -j ACCEPT' %
            (interface_name, interface_name),
            mask_rule, snat_rule]
        for r in nat_rules:
            if negate:
                self.assertNotIn(r.rule, expected_rules)
            else:
                self.assertIn(r.rule, expected_rules)
        expected_rules = [
            '-i %s -j MARK --set-xmark 0x2/%s' %
            (interface_name, lib_constants.ROUTER_MARK_MASK),
            '-o %s -m connmark --mark 0x0/%s -j CONNMARK '
            '--save-mark --nfmask %s --ctmask %s' %
            (interface_name,
             l3router.ADDRESS_SCOPE_MARK_MASK,
             l3router.ADDRESS_SCOPE_MARK_MASK,
             l3router.ADDRESS_SCOPE_MARK_MASK)]
        for r in mangle_rules:
            if negate:
                self.assertNotIn(r.rule, expected_rules)
            else:
                self.assertIn(r.rule, expected_rules)

    @mock.patch.object(dvr_router_base.LOG, 'error')
    def test_get_snat_port_for_internal_port(self, log_error):
        router = l3_test_common.prepare_router_data(num_internal_ports=4)
        self._set_ri_kwargs(mock.Mock(), router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        test_port = {
            'mac_address': '00:12:23:34:45:56',
            'fixed_ips': [{'subnet_id': l3_test_common.get_subnet_id(
                router[lib_constants.INTERFACE_KEY][0]),
                'ip_address': '101.12.13.14'}]}
        internal_ports = ri.router.get(lib_constants.INTERFACE_KEY, [])
        # test valid case
        with mock.patch.object(ri, 'get_snat_interfaces') as get_interfaces:
            get_interfaces.return_value = [test_port]
            res_port = ri.get_snat_port_for_internal_port(internal_ports[0])
            self.assertEqual(test_port, res_port)
            # test invalid case
            test_port['fixed_ips'][0]['subnet_id'] = 1234
            res_ip = ri.get_snat_port_for_internal_port(internal_ports[0])
            self.assertNotEqual(test_port, res_ip)
            self.assertIsNone(res_ip)
            self.assertTrue(log_error.called)

    @mock.patch.object(dvr_router.DvrEdgeRouter, 'load_used_fip_information')
    @mock.patch.object(dvr_router_base.LOG, 'error')
    def test_get_snat_port_for_internal_port_ipv6_same_port(self,
                                                            log_error,
                                                            load_used_fips):
        router = l3_test_common.prepare_router_data(
            ip_version=lib_constants.IP_VERSION_4, enable_snat=True,
            num_internal_ports=1)
        ri = dvr_router.DvrEdgeRouter(mock.sentinel.agent,
                                      HOSTNAME,
                                      router['id'],
                                      router,
                                      **self.ri_kwargs)

        # Add two additional IPv6 prefixes on the same interface
        l3_test_common.router_append_interface(
            router, count=2, ip_version=lib_constants.IP_VERSION_6,
            same_port=True)
        internal_ports = ri.router.get(lib_constants.INTERFACE_KEY, [])
        with mock.patch.object(ri, 'get_snat_interfaces') as get_interfaces:
            get_interfaces.return_value = internal_ports
            # get the second internal interface in the list
            res_port = ri.get_snat_port_for_internal_port(internal_ports[1])
            self.assertEqual(internal_ports[1], res_port)

            # tweak the first subnet_id, should still find port based
            # on second subnet_id
            test_port = copy.deepcopy(res_port)
            test_port['fixed_ips'][0]['subnet_id'] = 1234
            res_ip = ri.get_snat_port_for_internal_port(test_port)
            self.assertEqual(internal_ports[1], res_ip)

            # tweak the second subnet_id, shouldn't match now
            test_port['fixed_ips'][1]['subnet_id'] = 1234
            res_ip = ri.get_snat_port_for_internal_port(test_port)
            self.assertIsNone(res_ip)
            self.assertTrue(log_error.called)

    def test_process_cent_router(self):
        router = l3_test_common.prepare_router_data()
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = l3router.RouterInfo(agent, router['id'],
                                 router, **self.ri_kwargs)
        self._test_process_router(ri, agent)

    def test_process_dist_router(self):
        router = l3_test_common.prepare_router_data()
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        ri.snat_iptables_manager = iptables_manager.IptablesManager(
            namespace=ri.snat_namespace.name, use_ipv6=ri.use_ipv6)
        subnet_id = l3_test_common.get_subnet_id(
            router[lib_constants.INTERFACE_KEY][0])
        ri.router['distributed'] = True
        ri.router['_snat_router_interfaces'] = [{
            'fixed_ips': [{'subnet_id': subnet_id,
                           'ip_address': '1.2.3.4'}]}]
        ri.router['gw_port_host'] = None
        self._test_process_router(ri, agent, is_dvr_edge=True)

    def _test_process_router(self, ri, agent, is_dvr_edge=False):
        router = ri.router
        agent.host = HOSTNAME
        fake_fip_id = 'fake_fip_id'
        ri.create_dvr_external_gateway_on_agent = mock.Mock()
        ri.process_floating_ip_addresses = mock.Mock()
        ri.process_floating_ip_nat_rules = mock.Mock()
        ri.process_floating_ip_nat_rules_for_centralized_floatingip = (
            mock.Mock())
        ri.process_floating_ip_addresses.return_value = {
            fake_fip_id: 'ACTIVE'}
        ri.external_gateway_added = mock.Mock()
        ri.external_gateway_updated = mock.Mock()
        ri.process_address_scope = mock.Mock()
        fake_floatingips1 = {'floatingips': [
            {'id': fake_fip_id,
             'floating_ip_address': '8.8.8.8',
             'fixed_ip_address': '7.7.7.7',
             'port_id': _uuid(),
             'host': HOSTNAME}]}
        ri.process()
        ri.process_floating_ip_addresses.assert_called_with(mock.ANY)
        ri.process_floating_ip_addresses.reset_mock()
        if not is_dvr_edge:
            ri.process_floating_ip_nat_rules.assert_called_with()
            ri.process_floating_ip_nat_rules.reset_mock()
        elif ri.router.get('gw_port_host') == agent.host:
            ri.process_floating_ip_nat_rules_for_centralized_floatingip. \
                assert_called_with()
            ri.process_floating_ip_nat_rules_for_centralized_floatingip. \
                reset_mock()
        ri.external_gateway_added.reset_mock()

        # remap floating IP to a new fixed ip
        fake_floatingips2 = copy.deepcopy(fake_floatingips1)
        fake_floatingips2['floatingips'][0]['fixed_ip_address'] = '7.7.7.8'

        router[lib_constants.FLOATINGIP_KEY] = fake_floatingips2['floatingips']
        ri.process()
        ri.process_floating_ip_addresses.assert_called_with(mock.ANY)
        ri.process_floating_ip_addresses.reset_mock()
        if not is_dvr_edge:
            ri.process_floating_ip_nat_rules.assert_called_with()
            ri.process_floating_ip_nat_rules.reset_mock()
        elif ri.router.get('gw_port_host') == agent.host:
            ri.process_floating_ip_nat_rules_for_centralized_floatingip. \
                assert_called_with()
            ri.process_floating_ip_nat_rules_for_centralized_floatingip. \
                reset_mock()
        self.assertEqual(0, ri.external_gateway_added.call_count)
        self.assertEqual(0, ri.external_gateway_updated.call_count)
        ri.external_gateway_added.reset_mock()
        ri.external_gateway_updated.reset_mock()

        # change the ex_gw_port a bit to test gateway update
        new_gw_port = copy.deepcopy(ri.router['gw_port'])
        ri.router['gw_port'] = new_gw_port
        old_ip = (netaddr.IPAddress(ri.router['gw_port']
                                    ['fixed_ips'][0]['ip_address']))
        ri.router['gw_port']['fixed_ips'][0]['ip_address'] = str(old_ip + 1)

        ri.process()
        ri.process_floating_ip_addresses.reset_mock()
        ri.process_floating_ip_nat_rules.reset_mock()
        self.assertEqual(0, ri.external_gateway_added.call_count)
        self.assertEqual(1, ri.external_gateway_updated.call_count)

        # remove just the floating ips
        del router[lib_constants.FLOATINGIP_KEY]
        ri.process()
        ri.process_floating_ip_addresses.assert_called_with(mock.ANY)
        ri.process_floating_ip_addresses.reset_mock()
        if not is_dvr_edge:
            ri.process_floating_ip_nat_rules.assert_called_with()
            ri.process_floating_ip_nat_rules.reset_mock()
        elif ri.router.get('gw_port_host') == agent.host:
            ri.process_floating_ip_nat_rules_for_centralized_floatingip. \
                assert_called_with()
            ri.process_floating_ip_nat_rules_for_centralized_floatingip. \
                reset_mock()

        # now no ports so state is torn down
        del router[lib_constants.INTERFACE_KEY]
        del router['gw_port']
        ri.process()
        self.assertEqual(1, self.send_adv_notif.call_count)
        distributed = ri.router.get('distributed', False)
        self.assertEqual(distributed, ri.process_floating_ip_addresses.called)
        self.assertEqual(distributed, ri.process_floating_ip_nat_rules.called)

    def _test_process_floating_ip_addresses_add(self, ri, agent):
        floating_ips = ri.get_floating_ips()
        fip_id = floating_ips[0]['id']
        device = self.mock_ip_dev
        device.addr.list.return_value = []
        ri.iptables_manager.ipv4['nat'] = mock.MagicMock()
        ex_gw_port = {'id': _uuid(), 'network_id': mock.sentinel.ext_net_id}

        ri.add_floating_ip = mock.Mock(
            return_value=lib_constants.FLOATINGIP_STATUS_ACTIVE)
        with mock.patch.object(lla.LinkLocalAllocator, '_write'):
            if ri.router['distributed']:
                ri.fip_ns = agent.get_fip_ns(ex_gw_port['network_id'])
                ri.create_dvr_external_gateway_on_agent(ex_gw_port)
            fip_statuses = ri.process_floating_ip_addresses(
                mock.sentinel.interface_name)
        self.assertEqual({fip_id: lib_constants.FLOATINGIP_STATUS_ACTIVE},
                         fip_statuses)
        ri.add_floating_ip.assert_called_once_with(
            floating_ips[0], mock.sentinel.interface_name, device)

    @mock.patch.object(lla.LinkLocalAllocator, '_write')
    def test_create_dvr_fip_interfaces_if_fipnamespace_exist(self, lla_write):
        fake_network_id = _uuid()
        subnet_id = _uuid()
        fake_floatingips = {'floatingips': [
            {'id': _uuid(),
             'floating_ip_address': '20.0.0.3',
             'fixed_ip_address': '192.168.0.1',
             'floating_network_id': _uuid(),
             'port_id': _uuid(),
             'host': HOSTNAME}]}
        agent_gateway_port = (
            [{'fixed_ips': [
                {'ip_address': '20.0.0.30',
                 'prefixlen': 24,
                 'subnet_id': subnet_id}],
              'subnets': [
                  {'id': subnet_id,
                   'cidr': '20.0.0.0/24',
                   'gateway_ip': '20.0.0.1'}],
              'id': _uuid(),
              'network_id': fake_network_id,
              'mtu': 1500,
              'mac_address': 'ca:fe:de:ad:be:ef'}]
        )

        router = l3_test_common.prepare_router_data(enable_snat=True)
        router[lib_constants.FLOATINGIP_KEY] = fake_floatingips['floatingips']
        router[lib_constants.FLOATINGIP_AGENT_INTF_KEY] = agent_gateway_port
        router['distributed'] = True
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        ext_gw_port = ri.router.get('gw_port')
        ri.fip_ns = agent.get_fip_ns(ext_gw_port['network_id'])
        agent.process_router_add = mock.Mock()
        ri.fip_ns.create_rtr_2_fip_link = mock.Mock()
        with mock.patch.object(ri, 'get_floating_ips') as fips, \
                mock.patch.object(ri.fip_ns,
                                  'create') as create_fip, \
                mock.patch.object(ri, 'get_floating_agent_gw_interface'
                                  ) as fip_gw_port:
            fips.return_value = fake_floatingips
            fip_gw_port.return_value = agent_gateway_port[0]
            ri.create_dvr_external_gateway_on_agent(ext_gw_port)
            ri.connect_rtr_2_fip()
            self.assertTrue(fip_gw_port.called)
            self.assertTrue(create_fip.called)
            self.assertEqual(agent_gateway_port[0],
                             ri.fip_ns.agent_gateway_port)
            self.assertTrue(ri.rtr_fip_connect)
            # Now let us associate the fip to the router
            ri.floating_ip_added_dist(fips, "192.168.0.1/32")
            # Now let us disassociate the fip from the router
            ri.floating_ip_removed_dist("192.168.0.1/32")
            # Calling create_dvr_external_gateway_interfaces again to make
            # sure that the fip namespace create is not called again.
            # If the create is not called again, that would contain
            # the duplicate rules configuration in the fip namespace.
            ri.create_dvr_external_gateway_on_agent(ext_gw_port)
            self.assertTrue(fip_gw_port.called)
            create_fip.assert_called_once_with()
            self.assertEqual(1, ri.fip_ns.create_rtr_2_fip_link.call_count)

    @mock.patch.object(lla.LinkLocalAllocator, '_write')
    def test_floating_ip_not_configured_if_no_host_or_dest_host(self,
                                                                lla_write):
        fake_network_id = _uuid()
        subnet_id = _uuid()
        fake_floatingips = {'floatingips': [
            {'id': _uuid(),
             'floating_ip_address': '20.0.0.3',
             'fixed_ip_address': '192.168.0.1',
             'floating_network_id': _uuid(),
             'port_id': _uuid()}]}
        agent_gateway_port = (
            [{'fixed_ips': [
                {'ip_address': '20.0.0.30',
                 'prefixlen': 24,
                 'subnet_id': subnet_id}],
              'subnets': [
                  {'id': subnet_id,
                   'cidr': '20.0.0.0/24',
                   'gateway_ip': '20.0.0.1'}],
              'id': _uuid(),
              'network_id': fake_network_id,
              'mac_address': 'ca:fe:de:ad:be:ef'}]
        )

        router = l3_test_common.prepare_router_data(enable_snat=True)
        router[lib_constants.FLOATINGIP_KEY] = fake_floatingips['floatingips']
        router[lib_constants.FLOATINGIP_AGENT_INTF_KEY] = agent_gateway_port
        router['distributed'] = True
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        ext_gw_port = ri.router.get('gw_port')
        ri.fip_ns = agent.get_fip_ns(ext_gw_port['network_id'])
        agent.process_router_add = mock.Mock()
        ri.fip_ns.create_rtr_2_fip_link = mock.Mock()
        with mock.patch.object(ri, 'get_floating_ips') as fips, \
                mock.patch.object(ri, 'get_floating_agent_gw_interface'
                                  ) as fip_gw_port, \
                mock.patch.object(ri,
                                  '_add_floating_ip_rule') as add_rule, \
                mock.patch.object(ri.fip_ns,
                                  'create') as create_fip:
            fips.return_value = fake_floatingips
            fip_gw_port.return_value = agent_gateway_port[0]
            ri.create_dvr_external_gateway_on_agent(ext_gw_port)
            ri.connect_rtr_2_fip()
            self.assertTrue(fip_gw_port.called)
            self.assertTrue(create_fip.called)
            self.assertEqual(agent_gateway_port[0],
                             ri.fip_ns.agent_gateway_port)
            self.assertTrue(ri.rtr_fip_connect)
            # Now let us associate the fip to the router
            status = ri.floating_ip_added_dist(fips, "192.168.0.1/32")
            self.assertIsNone(status)
            self.assertEqual(0, self.send_adv_notif.call_count)
            self.assertFalse(add_rule.called)

    @mock.patch.object(lla.LinkLocalAllocator, '_write')
    def test_floating_ip_centralized(self, lla_write):
        fake_network_id = _uuid()
        subnet_id = _uuid()
        fake_floatingips = {'floatingips': [
            {'id': _uuid(),
             'floating_ip_address': '20.0.0.3',
             'fixed_ip_address': '192.168.0.1',
             'floating_network_id': _uuid(),
             'port_id': _uuid(),
             'dvr_snat_bound': True,
             'host': None},
            {'id': _uuid(),
             'floating_ip_address': '20.0.0.4',
             'fixed_ip_address': '192.168.0.2',
             'floating_network_id': _uuid(),
             'port_id': _uuid(),
             'dvr_snat_bound': True,
             'host': None}]}
        agent_gateway_port = (
            [{'fixed_ips': [
                {'ip_address': '20.0.0.30',
                 'prefixlen': 24,
                 'subnet_id': subnet_id}],
              'subnets': [
                  {'id': subnet_id,
                   'cidr': '20.0.0.0/24',
                   'gateway_ip': '20.0.0.1'}],
              'id': _uuid(),
              'network_id': fake_network_id,
              'mac_address': 'ca:fe:de:ad:be:ef'}]
        )

        router = l3_test_common.prepare_router_data(enable_snat=True)
        router[lib_constants.FLOATINGIP_KEY] = fake_floatingips['floatingips']
        router[lib_constants.FLOATINGIP_AGENT_INTF_KEY] = agent_gateway_port
        router['distributed'] = True
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        ext_gw_port = ri.router.get('gw_port')
        ri.fip_ns = agent.get_fip_ns(ext_gw_port['network_id'])
        agent.process_router_add = mock.Mock()
        ri.fip_ns.create_rtr_2_fip_link = mock.Mock()
        with mock.patch.object(ri, 'get_floating_ips') as fips, \
                mock.patch.object(ri,
                                  'add_centralized_floatingip') as add_fip, \
                mock.patch.object(ri, 'get_centralized_fip_cidr_set'
                                  ) as get_fip_cidrs, \
                mock.patch.object(ri, 'get_floating_agent_gw_interface'
                                  ) as fip_gw_port, \
                mock.patch.object(ri.fip_ns,
                                  'create') as create_fip, \
                mock.patch.object(ri,
                                  'remove_centralized_floatingip') as rem_fip:
            fips.return_value = fake_floatingips
            fip_gw_port.return_value = agent_gateway_port[0]
            add_fip.return_value = lib_constants.FLOATINGIP_STATUS_ACTIVE
            ri.create_dvr_external_gateway_on_agent(ext_gw_port)
            ri.connect_rtr_2_fip()
            self.assertTrue(fip_gw_port.called)
            self.assertTrue(create_fip.called)
            self.assertEqual(agent_gateway_port[0],
                             ri.fip_ns.agent_gateway_port)
            self.assertTrue(ri.rtr_fip_connect)
            # Now let us associate the fip to the router
            status = ri.floating_ip_added_dist(fips, "192.168.0.1/32")
            add_fip.assert_called_once_with(fips, "192.168.0.1/32")
            self.assertEqual(lib_constants.FLOATINGIP_STATUS_ACTIVE, status)
            # Now let us add the second fip
            status = ri.floating_ip_added_dist(fips, "192.168.0.2/32")
            self.assertEqual(lib_constants.FLOATINGIP_STATUS_ACTIVE, status)
            device = mock.Mock()
            get_fip_cidrs.return_value = set(
                ["192.168.0.2/32", "192.168.0.1/32"])
            self.assertEqual(set(["192.168.0.2/32", "192.168.0.1/32"]),
                             ri.get_router_cidrs(device))
            ri.floating_ip_removed_dist("192.168.0.1/32")
            rem_fip.assert_called_once_with("192.168.0.1/32")
            self.assertTrue(get_fip_cidrs.called)
            get_fip_cidrs.return_value = set(["192.168.0.2/32"])
            self.assertEqual(set(["192.168.0.2/32"]),
                             ri.get_router_cidrs(device))

    @mock.patch.object(lla.LinkLocalAllocator, '_write')
    def test_create_dvr_fip_interfaces_for_late_binding(self, lla_write):
        fake_network_id = _uuid()
        fake_subnet_id = _uuid()
        fake_floatingips = {'floatingips': [
            {'id': _uuid(),
             'floating_ip_address': '20.0.0.3',
             'fixed_ip_address': '192.168.0.1',
             'floating_network_id': _uuid(),
             'port_id': _uuid(),
             'host': HOSTNAME}]}
        agent_gateway_port = (
            {'fixed_ips': [
                {'ip_address': '20.0.0.30',
                 'prefixlen': 24,
                 'subnet_id': fake_subnet_id}],
             'subnets': [
                 {'id': fake_subnet_id,
                  'cidr': '20.0.0.0/24',
                  'gateway_ip': '20.0.0.1'}],
             'id': _uuid(),
             'network_id': fake_network_id,
             'mtu': 1500,
             'mac_address': 'ca:fe:de:ad:be:ef'}
        )

        router = l3_test_common.prepare_router_data(enable_snat=True)
        router[lib_constants.FLOATINGIP_KEY] = fake_floatingips['floatingips']
        router[lib_constants.FLOATINGIP_AGENT_INTF_KEY] = []
        router['distributed'] = True
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)

        ext_gw_port = ri.router.get('gw_port')
        ri.fip_ns = agent.get_fip_ns(ext_gw_port['network_id'])
        ri.fip_ns.subscribe = mock.Mock()
        with mock.patch.object(agent.plugin_rpc,
                               'get_agent_gateway_port') as fip_gw_port:
            fip_gw_port.return_value = agent_gateway_port
            ri.create_dvr_external_gateway_on_agent(ext_gw_port)
            ri.connect_rtr_2_fip()
            self.assertTrue(fip_gw_port.called)
            self.assertTrue(ri.rtr_fip_connect)
            self.assertEqual(agent_gateway_port,
                             ri.fip_ns.agent_gateway_port)

    @mock.patch.object(lla.LinkLocalAllocator, '_write')
    def test_create_dvr_fip_interfaces(self, lla_write):
        fake_network_id = _uuid()
        subnet_id = _uuid()
        fake_floatingips = {'floatingips': [
            {'id': _uuid(),
             'floating_ip_address': '20.0.0.3',
             'fixed_ip_address': '192.168.0.1',
             'floating_network_id': _uuid(),
             'port_id': _uuid(),
             'host': HOSTNAME}]}
        agent_gateway_port = (
            [{'fixed_ips': [
                {'ip_address': '20.0.0.30',
                 'prefixlen': 24,
                 'subnet_id': subnet_id}],
              'subnets': [
                  {'id': subnet_id,
                   'cidr': '20.0.0.0/24',
                   'gateway_ip': '20.0.0.1'}],
              'id': _uuid(),
              'network_id': fake_network_id,
              'mtu': 1500,
              'mac_address': 'ca:fe:de:ad:be:ef'}]
        )

        router = l3_test_common.prepare_router_data(enable_snat=True)
        router[lib_constants.FLOATINGIP_KEY] = fake_floatingips['floatingips']
        router[lib_constants.FLOATINGIP_AGENT_INTF_KEY] = agent_gateway_port
        router['distributed'] = True
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)

        ext_gw_port = ri.router.get('gw_port')
        ri.fip_ns = agent.get_fip_ns(ext_gw_port['network_id'])
        ri.fip_ns.subscribe = mock.Mock()
        ri.fip_ns.agent_router_gateway = mock.Mock()
        agent.process_router_add = mock.Mock()

        with mock.patch.object(
                    ri,
                    'get_floating_agent_gw_interface') as fip_gw_port:
            fip_gw_port.return_value = agent_gateway_port[0]
            ri.create_dvr_external_gateway_on_agent(ext_gw_port)
            ri.connect_rtr_2_fip()
            self.assertTrue(fip_gw_port.called)
            self.assertEqual(agent_gateway_port[0],
                             ri.fip_ns.agent_gateway_port)
            self.assertTrue(ri.rtr_fip_connect)
            self.assertTrue(ri.rtr_fip_subnet)

    @mock.patch.object(lla.LinkLocalAllocator, '_write')
    def test_create_dvr_fip_interfaces_for_restart_l3agent_case(self,
                                                                lla_write):
        fake_floatingips = {'floatingips': [
            {'id': _uuid(),
             'floating_ip_address': '20.0.0.3',
             'fixed_ip_address': '192.168.0.1',
             'floating_network_id': _uuid(),
             'port_id': _uuid(),
             'host': HOSTNAME}]}
        agent_gateway_port = (
            [{'fixed_ips': [
                {'ip_address': '20.0.0.30',
                 'prefixlen': 24,
                 'subnet_id': 'subnet_id'}],
              'subnets': [
                  {'id': 'subnet_id',
                   'cidr': '20.0.0.0/24',
                   'gateway_ip': '20.0.0.1'}],
              'id': _uuid(),
              'network_id': 'fake_network_id',
              'mtu': 1500,
              'mac_address': 'ca:fe:de:ad:be:ef'}]
        )

        router = l3_test_common.prepare_router_data(enable_snat=True)
        router[lib_constants.FLOATINGIP_KEY] = fake_floatingips['floatingips']
        router[lib_constants.FLOATINGIP_AGENT_INTF_KEY] = agent_gateway_port
        router['distributed'] = True
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        ext_gw_port = ri.router.get('gw_port')
        ri.fip_ns = agent.get_fip_ns(ext_gw_port['network_id'])
        ri.fip_ns.subscribe = mock.Mock(return_value=True)
        ri.fip_ns.agent_router_gateway = mock.Mock()
        ri.rtr_fip_subnet = None

        with mock.patch.object(
                    ri, 'get_floating_agent_gw_interface') as fip_gw_port:
            fip_gw_port.return_value = agent_gateway_port[0]
            ri.create_dvr_external_gateway_on_agent(ext_gw_port)
            ri.connect_rtr_2_fip()
            self.assertTrue(fip_gw_port.called)
            self.assertEqual(agent_gateway_port[0],
                             ri.fip_ns.agent_gateway_port)
            self.assertTrue(ri.rtr_fip_subnet)
            self.assertTrue(ri.rtr_fip_connect)

    def test_process_router_cent_floating_ip_add(self):
        fake_floatingips = {'floatingips': [
            {'id': _uuid(),
             'floating_ip_address': '15.1.2.3',
             'fixed_ip_address': '192.168.0.1',
             'status': 'DOWN',
             'floating_network_id': _uuid(),
             'port_id': _uuid(),
             'host': HOSTNAME}]}

        router = l3_test_common.prepare_router_data(enable_snat=True)
        router[lib_constants.FLOATINGIP_KEY] = fake_floatingips['floatingips']
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = l3router.RouterInfo(agent, router['id'],
                                 router, **self.ri_kwargs)
        ri.iptables_manager.ipv4['nat'] = mock.MagicMock()
        ri.get_external_device_name = mock.Mock(return_value='exgw')
        self._test_process_floating_ip_addresses_add(ri, agent)

    def _test_process_router_snat_disabled(self, random_fully):
        iptables_manager.IptablesManager.random_fully = random_fully
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data(enable_snat=True)
        ri = l3router.RouterInfo(agent, router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        # Process with NAT
        ri.process()
        orig_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]
        orig_mangle_rules = ri.iptables_manager.ipv4['mangle'].rules[:]
        # Reprocess without NAT
        router['enable_snat'] = False
        # Reassign the router object to RouterInfo
        ri.router = router
        ri.process()
        # For some reason set logic does not work well with
        # IpTablesRule instances
        nat_rules_delta = [r for r in orig_nat_rules
                           if r not in ri.iptables_manager.ipv4['nat'].rules]
        self.assertEqual(1, len(nat_rules_delta))
        mangle_rules_delta = [
            r for r in orig_mangle_rules
            if r not in ri.iptables_manager.ipv4['mangle'].rules]
        self.assertEqual(1, len(mangle_rules_delta))
        self._verify_snat_mangle_rules(nat_rules_delta, mangle_rules_delta,
                                       router, random_fully)
        self.assertEqual(1, self.send_adv_notif.call_count)

    def test_process_router_snat_disabled_random_fully(self):
        self._test_process_router_snat_disabled(True)

    def test_process_router_snat_disabled_random_fully_false(self):
        self._test_process_router_snat_disabled(False)

    def _test_process_router_snat_enabled(self, random_fully):
        iptables_manager.IptablesManager.random_fully = random_fully
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data(enable_snat=False)
        ri = l3router.RouterInfo(agent, router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        # Process without NAT
        ri.process()
        orig_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]
        orig_mangle_rules = ri.iptables_manager.ipv4['mangle'].rules[:]
        # Reprocess with NAT
        router['enable_snat'] = True
        # Reassign the router object to RouterInfo
        ri.router = router
        ri.process()
        # For some reason set logic does not work well with
        # IpTablesRule instances
        nat_rules_delta = [r for r in ri.iptables_manager.ipv4['nat'].rules
                           if r not in orig_nat_rules]
        self.assertEqual(1, len(nat_rules_delta))
        mangle_rules_delta = [
            r for r in ri.iptables_manager.ipv4['mangle'].rules
            if r not in orig_mangle_rules]
        self.assertEqual(1, len(mangle_rules_delta))
        self._verify_snat_mangle_rules(nat_rules_delta, mangle_rules_delta,
                                       router, random_fully)
        self.assertEqual(1, self.send_adv_notif.call_count)

    def test_process_router_snat_enabled_random_fully(self):
        self._test_process_router_snat_enabled(True)

    def test_process_router_snat_enabled_random_fully_false(self):
        self._test_process_router_snat_enabled(False)

    def _test_update_routing_table(self, is_snat_host=True):
        router = l3_test_common.prepare_router_data()
        uuid = router['id']
        s_netns = 'snat-' + uuid
        q_netns = 'qrouter-' + uuid
        fake_route1 = {'destination': '135.207.0.0/16',
                       'nexthop': '19.4.4.200'}
        calls = [mock.call('replace', fake_route1, q_netns)]
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self._set_ri_kwargs(agent, uuid, router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        ri._update_routing_table = mock.Mock()

        with mock.patch.object(ri, '_is_this_snat_host') as snat_host:
            snat_host.return_value = is_snat_host
            ri.update_routing_table('replace', fake_route1)
            if is_snat_host:
                ri._update_routing_table('replace', fake_route1, s_netns)
                calls += [mock.call('replace', fake_route1, s_netns)]
            ri._update_routing_table.assert_has_calls(calls, any_order=True)

    def test_process_update_snat_routing_table(self):
        self._test_update_routing_table()

    def test_process_not_update_snat_routing_table(self):
        self._test_update_routing_table(is_snat_host=False)

    def test_process_router_interface_added(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data()
        ri = l3router.RouterInfo(agent, router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        # Process with NAT
        ri.process()
        # Add an interface and reprocess
        l3_test_common.router_append_interface(router)
        # Reassign the router object to RouterInfo
        ri.router = router
        ri.process()
        # send_ip_addr_adv_notif is called both times process is called
        self.assertEqual(2, self.send_adv_notif.call_count)

    def _test_process_ipv6_only_or_dual_stack_gw(self, dual_stack=False):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data(
            ip_version=lib_constants.IP_VERSION_6, dual_stack=dual_stack)
        # Get NAT rules without the gw_port
        gw_port = router['gw_port']
        router['gw_port'] = None
        ri = l3router.RouterInfo(agent, router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        self._process_router_instance_for_agent(agent, ri, router)
        orig_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]

        # Get NAT rules with the gw_port
        router['gw_port'] = gw_port
        ri = l3router.RouterInfo(agent, router['id'], router, **self.ri_kwargs)
        p = ri.external_gateway_nat_fip_rules
        s = ri.external_gateway_nat_snat_rules
        attrs_to_mock = dict(
            (a, mock.DEFAULT) for a in
            ['external_gateway_nat_fip_rules',
             'external_gateway_nat_snat_rules']
        )
        with mock.patch.multiple(ri, **attrs_to_mock) as mocks:
            mocks['external_gateway_nat_fip_rules'].side_effect = p
            mocks['external_gateway_nat_snat_rules'].side_effect = s
            self._process_router_instance_for_agent(agent, ri, router)
            new_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]

            # NAT rules should only change for dual_stack operation
            if dual_stack:
                self.assertTrue(
                    mocks['external_gateway_nat_fip_rules'].called)
                self.assertTrue(
                    mocks['external_gateway_nat_snat_rules'].called)
                self.assertNotEqual(orig_nat_rules, new_nat_rules)
            else:
                self.assertFalse(
                    mocks['external_gateway_nat_fip_rules'].called)
                self.assertFalse(
                    mocks['external_gateway_nat_snat_rules'].called)
                self.assertEqual(orig_nat_rules, new_nat_rules)

    def test_process_ipv6_only_gw(self):
        self._test_process_ipv6_only_or_dual_stack_gw()

    def test_process_dual_stack_gw(self):
        self._test_process_ipv6_only_or_dual_stack_gw(dual_stack=True)

    def _process_router_ipv6_interface_added(
            self, router, ra_mode=None, addr_mode=None):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = l3router.RouterInfo(agent, router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        # Process with NAT
        ri.process()
        orig_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]
        # Add an IPv6 interface and reprocess
        l3_test_common.router_append_interface(
            router, count=1, ip_version=lib_constants.IP_VERSION_6,
            ra_mode=ra_mode, addr_mode=addr_mode)
        # Reassign the router object to RouterInfo
        self._process_router_instance_for_agent(agent, ri, router)
        # IPv4 NAT rules should not be changed by adding an IPv6 interface
        nat_rules_delta = [r for r in ri.iptables_manager.ipv4['nat'].rules
                           if r not in orig_nat_rules]
        self.assertFalse(nat_rules_delta)
        return ri

    def _radvd_expected_call_external_process(self, ri, enable=True):
        expected_calls = [mock.call(uuid=ri.router['id'],
                          service='radvd',
                          default_cmd_callback=mock.ANY,
                          namespace=ri.ns_name,
                          conf=mock.ANY,
                          run_as_root=True)]
        if enable:
            expected_calls.append(mock.call().enable(reload_cfg=True))
        else:
            expected_calls.append(mock.call().disable())
        return expected_calls

    def _process_router_ipv6_subnet_added(self, router,
            ipv6_subnet_modes=None, dns_nameservers=None, network_mtu=0):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = l3router.RouterInfo(agent, router['id'], router, **self.ri_kwargs)
        agent.external_gateway_added = mock.Mock()
        self._process_router_instance_for_agent(agent, ri, router)
        # Add an IPv6 interface with len(ipv6_subnet_modes) subnets
        # and reprocess
        l3_test_common.router_append_subnet(
            router,
            count=len(ipv6_subnet_modes),
            ip_version=lib_constants.IP_VERSION_6,
            ipv6_subnet_modes=ipv6_subnet_modes,
            dns_nameservers=dns_nameservers,
            network_mtu=network_mtu)
        # Reassign the router object to RouterInfo
        self._process_router_instance_for_agent(agent, ri, router)
        return ri

    def _assert_ri_process_enabled(self, ri):
        """Verify that process was enabled for a router instance."""
        expected_calls = self._radvd_expected_call_external_process(ri)
        self.assertEqual(expected_calls, self.external_process.mock_calls)

    def _assert_ri_process_disabled(self, ri):
        """Verify that process was disabled for a router instance."""
        expected_calls = self._radvd_expected_call_external_process(ri, False)
        self.assertEqual(expected_calls, self.external_process.mock_calls)

    def test_process_router_ipv6_interface_added(self):
        router = l3_test_common.prepare_router_data()
        ri = self._process_router_ipv6_interface_added(router)
        self._assert_ri_process_enabled(ri)
        # Expect radvd configured without prefix
        self.assertNotIn('prefix', self.utils_replace_file.call_args[0][1])

    def test_process_router_ipv6_slaac_interface_added(self):
        router = l3_test_common.prepare_router_data()
        ri = self._process_router_ipv6_interface_added(
            router, ra_mode=lib_constants.IPV6_SLAAC)
        self._assert_ri_process_enabled(ri)
        # Expect radvd configured with prefix
        radvd_config_str = self.utils_replace_file.call_args[0][1]
        self.assertIn('prefix', radvd_config_str)
        self.assertIn('AdvAutonomous on', radvd_config_str)

    def test_process_router_ipv6_dhcpv6_stateful_interface_added(self):
        router = l3_test_common.prepare_router_data()
        ri = self._process_router_ipv6_interface_added(
            router, ra_mode=lib_constants.DHCPV6_STATEFUL)
        self._assert_ri_process_enabled(ri)
        # Expect radvd configured with prefix
        radvd_config_str = self.utils_replace_file.call_args[0][1]
        self.assertIn('prefix', radvd_config_str)
        self.assertIn('AdvAutonomous off', radvd_config_str)

    def test_process_router_ipv6_subnets_added(self):
        router = l3_test_common.prepare_router_data()
        ri = self._process_router_ipv6_subnet_added(router, ipv6_subnet_modes=[
            {'ra_mode': lib_constants.IPV6_SLAAC,
             'address_mode': lib_constants.IPV6_SLAAC},
            {'ra_mode': lib_constants.DHCPV6_STATELESS,
             'address_mode': lib_constants.DHCPV6_STATELESS},
            {'ra_mode': lib_constants.DHCPV6_STATEFUL,
             'address_mode': lib_constants.DHCPV6_STATEFUL}])
        self._assert_ri_process_enabled(ri)
        radvd_config_str = self.utils_replace_file.call_args[0][1]
        # Assert we have a prefix from IPV6_SLAAC and a prefix from
        # DHCPV6_STATELESS on one interface
        self.assertEqual(3, radvd_config_str.count("prefix"))
        self.assertEqual(1, radvd_config_str.count("interface"))
        self.assertEqual(2, radvd_config_str.count("AdvAutonomous on"))
        self.assertEqual(1, radvd_config_str.count("AdvAutonomous off"))

    def test_process_router_ipv6_subnets_added_to_existing_port(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data()
        ri = l3router.RouterInfo(agent, router['id'], router, **self.ri_kwargs)
        agent.external_gateway_added = mock.Mock()
        self._process_router_instance_for_agent(agent, ri, router)
        # Add the first subnet on a new interface
        l3_test_common.router_append_subnet(
            router, count=1,
            ip_version=lib_constants.IP_VERSION_6, ipv6_subnet_modes=[
                {'ra_mode': lib_constants.IPV6_SLAAC,
                 'address_mode': lib_constants.IPV6_SLAAC}])
        self._process_router_instance_for_agent(agent, ri, router)
        self._assert_ri_process_enabled(ri)
        radvd_config = self.utils_replace_file.call_args[0][1].split()
        self.assertEqual(1, len(ri.internal_ports[1]['subnets']))
        self.assertEqual(1, len(ri.internal_ports[1]['fixed_ips']))
        self.assertEqual(1, radvd_config.count("prefix"))
        self.assertEqual(1, radvd_config.count("interface"))
        # Reset mocks to verify radvd enabled and configured correctly
        # after second subnet added to interface
        self.external_process.reset_mock()
        self.utils_replace_file.reset_mock()
        # Add the second subnet on the same interface
        interface_id = router[lib_constants.INTERFACE_KEY][1]['id']
        l3_test_common.router_append_subnet(
            router, count=1,
            ip_version=lib_constants.IP_VERSION_6,
            ipv6_subnet_modes=[
                {'ra_mode': lib_constants.IPV6_SLAAC,
                 'address_mode': lib_constants.IPV6_SLAAC}],
            interface_id=interface_id)
        self._process_router_instance_for_agent(agent, ri, router)
        # radvd should have been enabled again and the interface
        # should have two prefixes
        self._assert_ri_process_enabled(ri)
        radvd_config = self.utils_replace_file.call_args[0][1].split()
        self.assertEqual(2, len(ri.internal_ports[1]['subnets']))
        self.assertEqual(2, len(ri.internal_ports[1]['fixed_ips']))
        self.assertEqual(2, radvd_config.count("prefix"))
        self.assertEqual(1, radvd_config.count("interface"))

    def test_process_router_ipv6v4_interface_added(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data()
        ri = l3router.RouterInfo(agent, router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        # Process with NAT
        ri.process()
        # Add an IPv4 and IPv6 interface and reprocess
        l3_test_common.router_append_interface(
            router, count=1, ip_version=lib_constants.IP_VERSION_4)
        l3_test_common.router_append_interface(
            router, count=1, ip_version=lib_constants.IP_VERSION_6)
        # Reassign the router object to RouterInfo
        self._process_router_instance_for_agent(agent, ri, router)
        self._assert_ri_process_enabled(ri)

    def test_process_router_interface_removed(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        ri = l3router.RouterInfo(agent, router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        # Process with NAT
        ri.process()
        # Add an interface and reprocess
        del router[lib_constants.INTERFACE_KEY][1]
        # Reassign the router object to RouterInfo
        ri.router = router
        ri.process()
        # send_ip_addr_adv_notif is called both times process is called
        self.assertEqual(2, self.send_adv_notif.call_count)

    def test_process_router_ipv6_interface_removed(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data()
        ri = l3router.RouterInfo(agent, router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        self._process_router_instance_for_agent(agent, ri, router)
        # Add an IPv6 interface and reprocess
        l3_test_common.router_append_interface(
            router, count=1, ip_version=lib_constants.IP_VERSION_6)
        self._process_router_instance_for_agent(agent, ri, router)
        self._assert_ri_process_enabled(ri)
        # Reset the calls so we can check for disable radvd
        self.external_process.reset_mock()
        self.process_monitor.reset_mock()
        # Remove the IPv6 interface and reprocess
        del router[lib_constants.INTERFACE_KEY][1]
        self._process_router_instance_for_agent(agent, ri, router)
        self._assert_ri_process_disabled(ri)

    def test_process_router_ipv6_subnet_removed(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data()
        ri = l3router.RouterInfo(agent, router['id'], router, **self.ri_kwargs)
        agent.external_gateway_added = mock.Mock()
        self._process_router_instance_for_agent(agent, ri, router)
        # Add an IPv6 interface with two subnets and reprocess
        l3_test_common.router_append_subnet(
            router, count=2, ip_version=lib_constants.IP_VERSION_6,
            ipv6_subnet_modes=([{'ra_mode': lib_constants.IPV6_SLAAC,
                                 'address_mode': lib_constants.IPV6_SLAAC}] *
                               2))
        self._process_router_instance_for_agent(agent, ri, router)
        self._assert_ri_process_enabled(ri)
        # Reset mocks to check for modified radvd config
        self.utils_replace_file.reset_mock()
        self.external_process.reset_mock()
        # Remove one subnet from the interface and reprocess
        interfaces = copy.deepcopy(router[lib_constants.INTERFACE_KEY])
        del interfaces[1]['subnets'][0]
        del interfaces[1]['fixed_ips'][0]
        router[lib_constants.INTERFACE_KEY] = interfaces
        self._process_router_instance_for_agent(agent, ri, router)
        # Assert radvd was enabled again and that we only have one
        # prefix on the interface
        self._assert_ri_process_enabled(ri)
        radvd_config = self.utils_replace_file.call_args[0][1].split()
        self.assertEqual(1, len(ri.internal_ports[1]['subnets']))
        self.assertEqual(1, len(ri.internal_ports[1]['fixed_ips']))
        self.assertEqual(1, radvd_config.count("interface"))
        self.assertEqual(1, radvd_config.count("prefix"))

    def test_process_router_internal_network_added_unexpected_error(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data()
        ri = l3router.RouterInfo(agent, router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        with mock.patch.object(
                ri,
                'internal_network_added') as internal_network_added:
            # raise RuntimeError to simulate that an unexpected exception
            # occurs
            internal_network_added.side_effect = RuntimeError
            self.assertRaises(RuntimeError, ri.process)
            self.assertNotIn(
                router[lib_constants.INTERFACE_KEY][0], ri.internal_ports)

            # The unexpected exception has been fixed manually
            internal_network_added.side_effect = None

            # periodic_sync_routers_task finds out that _rpc_loop failed to
            # process the router last time, it will retry in the next run.
            ri.process()
            # We were able to add the port to ri.internal_ports
            self.assertIn(
                router[lib_constants.INTERFACE_KEY][0], ri.internal_ports)

    def test_process_router_internal_network_removed_unexpected_error(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data()
        ri = l3router.RouterInfo(agent, router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        # add an internal port
        ri.process()

        with mock.patch.object(
                ri,
                'internal_network_removed') as internal_net_removed:
            # raise RuntimeError to simulate that an unexpected exception
            # occurs
            internal_net_removed.side_effect = RuntimeError
            ri.internal_ports[0]['admin_state_up'] = False
            # The above port is set to down state, remove it.
            self.assertRaises(RuntimeError, ri.process)
            self.assertIn(
                router[lib_constants.INTERFACE_KEY][0], ri.internal_ports)

            # The unexpected exception has been fixed manually
            internal_net_removed.side_effect = None

            # periodic_sync_routers_task finds out that _rpc_loop failed to
            # process the router last time, it will retry in the next run.
            ri.process()
            # We were able to remove the port from ri.internal_ports
            self.assertNotIn(
                router[lib_constants.INTERFACE_KEY][0], ri.internal_ports)

    def test_process_router_floatingip_nochange(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data(num_internal_ports=1)
        fip1 = {'id': _uuid(), 'floating_ip_address': '8.8.8.8',
                'fixed_ip_address': '7.7.7.7', 'status': 'ACTIVE',
                'port_id': router[lib_constants.INTERFACE_KEY][0]['id']}
        fip2 = copy.copy(fip1)
        fip2.update({'id': _uuid(), 'status': 'DOWN',
                     'floating_ip_address': '9.9.9.9'})
        router[lib_constants.FLOATINGIP_KEY] = [fip1, fip2]

        ri = legacy_router.LegacyRouter(agent, router['id'], router,
                                        **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        with mock.patch.object(
            agent.plugin_rpc, 'update_floatingip_statuses'
        ) as mock_update_fip_status,\
                mock.patch.object(
                    ri, 'get_centralized_fip_cidr_set') as cent_cidrs,\
                mock.patch.object(ri, 'get_router_cidrs') as mock_get_cidrs:
            cent_cidrs.return_value = set()
            mock_get_cidrs.return_value = set(
                [fip1['floating_ip_address'] + '/32'])
            ri.process()
            # make sure only the one that wasn't in existing cidrs was sent
            mock_update_fip_status.assert_called_once_with(
                mock.ANY, ri.router_id, {fip2['id']: 'ACTIVE'})

    @mock.patch.object(l3_agent.LOG, 'exception')
    def _retrigger_initialize(self, log_exception, delete_fail=False):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = {'id': _uuid(),
                  'external_gateway_info': {'network_id': 'aaa'}}
        self.plugin_api.get_routers.return_value = [router]
        update = resource_processing_queue.ResourceUpdate(
            router['id'],
            l3_agent.PRIORITY_SYNC_ROUTERS_TASK,
            resource=router,
            timestamp=timeutils.utcnow())
        agent._queue.add(update)

        ri = legacy_router.LegacyRouter(agent, router['id'], router,
                                        **self.ri_kwargs)
        calls = [mock.call('Error while initializing router %s',
                           router['id'])]
        if delete_fail:
            # if delete fails, then also retrigger initialize
            ri.delete = mock.Mock(side_effect=RuntimeError())
            calls.append(
                 mock.call('Error while deleting router %s',
                           router['id']))
        else:
            ri.delete = mock.Mock()
        calls.append(
            mock.call('Failed to process compatible router: %s' %
                      router['id']))
        ri.process = mock.Mock()
        ri.initialize = mock.Mock(side_effect=RuntimeError())
        agent._create_router = mock.Mock(return_value=ri)
        agent._fetch_external_net_id = mock.Mock(
            return_value=router['external_gateway_info']['network_id'])
        agent._process_router_update()
        log_exception.assert_has_calls(calls)

        ri.initialize.side_effect = None
        agent._process_router_update()
        self.assertTrue(ri.delete.called)
        self.assertEqual(2, ri.initialize.call_count)
        self.assertEqual(2, agent._create_router.call_count)
        self.assertEqual(1, ri.process.call_count)
        self.assertIn(ri.router_id, agent.router_info)

    def test_initialize_fail_retrigger_initialize(self):
        self._retrigger_initialize()

    def test_initialize_and_delete_fail_retrigger_initialize(self):
        self._retrigger_initialize(delete_fail=True)

    def test_process_router_floatingip_status_update_if_processed(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data(num_internal_ports=1)
        fip1 = {'id': _uuid(), 'floating_ip_address': '8.8.8.8',
                'fixed_ip_address': '7.7.7.7', 'status': 'ACTIVE',
                'port_id': router[lib_constants.INTERFACE_KEY][0]['id']}
        fip2 = copy.copy(fip1)
        fip2.update({'id': _uuid(), 'status': 'DOWN', })
        router[lib_constants.FLOATINGIP_KEY] = [fip1, fip2]

        ri = legacy_router.LegacyRouter(agent, router['id'], router,
                                        **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        ri.iptables_manager.ipv4['nat'] = mock.MagicMock()
        with mock.patch.object(
            agent.plugin_rpc, 'update_floatingip_statuses'
        ) as mock_update_fip_status,\
                mock.patch.object(
                    ri, 'get_centralized_fip_cidr_set') as cent_cidrs,\
                mock.patch.object(ri, 'get_router_cidrs') as mock_get_cidrs:
            mock_get_cidrs.return_value = set()
            cent_cidrs.return_value = set()
            ri.process()
            # make sure both was sent since not existed in existing cidrs
            mock_update_fip_status.assert_called_once_with(
                mock.ANY, ri.router_id, {fip1['id']: 'ACTIVE',
                                         fip2['id']: 'ACTIVE'})

    def test_process_router_floatingip_disabled(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        with mock.patch.object(agent.plugin_rpc,
                'update_floatingip_statuses') as mock_update_fip_status:
            fip_id = _uuid()
            router = l3_test_common.prepare_router_data(num_internal_ports=1)
            router[lib_constants.FLOATINGIP_KEY] = [
                {'id': fip_id,
                 'floating_ip_address': '8.8.8.8',
                 'fixed_ip_address': '7.7.7.7',
                 'status': 'DOWN',
                 'port_id': router[lib_constants.INTERFACE_KEY][0]['id']}]

            ri = legacy_router.LegacyRouter(agent, router['id'],
                                            router,
                                            **self.ri_kwargs)
            ri.external_gateway_added = mock.Mock()
            ri.process()
            # Assess the call for putting the floating IP up was performed
            mock_update_fip_status.assert_called_once_with(
                mock.ANY, ri.router_id,
                {fip_id: lib_constants.FLOATINGIP_STATUS_ACTIVE})
            mock_update_fip_status.reset_mock()
            # Process the router again, this time without floating IPs
            router[lib_constants.FLOATINGIP_KEY] = []
            ri.router = router
            ri.process()
            # Assess the call for putting the floating IP up was performed
            mock_update_fip_status.assert_called_once_with(
                mock.ANY, ri.router_id,
                {fip_id: lib_constants.FLOATINGIP_STATUS_DOWN})

    def test_process_router_floatingip_exception(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        with mock.patch.object(agent.plugin_rpc,
                'update_floatingip_statuses') as mock_update_fip_status:
            fip_id = _uuid()
            router = l3_test_common.prepare_router_data(num_internal_ports=1)
            router[lib_constants.FLOATINGIP_KEY] = [
                {'id': fip_id,
                 'floating_ip_address': '8.8.8.8',
                 'fixed_ip_address': '7.7.7.7',
                 'port_id': router[lib_constants.INTERFACE_KEY][0]['id']}]

            ri = l3router.RouterInfo(agent, router['id'],
                                     router, **self.ri_kwargs)
            ri.process_floating_ip_addresses = mock.Mock(
                side_effect=RuntimeError)
            ri.external_gateway_added = mock.Mock()
            ri.process()
            # Assess the call for putting the floating IP into Error
            # was performed
            mock_update_fip_status.assert_called_once_with(
                mock.ANY, ri.router_id,
                {fip_id: lib_constants.FLOATINGIP_STATUS_ERROR})

    def test_process_external_iptables_exception(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        with mock.patch.object(agent.plugin_rpc,
                'update_floatingip_statuses') as mock_update_fip_status:
            fip_id = _uuid()
            router = l3_test_common.prepare_router_data(num_internal_ports=1)
            router[lib_constants.FLOATINGIP_KEY] = [
                {'id': fip_id,
                 'floating_ip_address': '8.8.8.8',
                 'fixed_ip_address': '7.7.7.7',
                 'port_id': router[lib_constants.INTERFACE_KEY][0]['id']}]

            ri = l3router.RouterInfo(agent, router['id'],
                                     router, **self.ri_kwargs)
            ri.iptables_manager._apply = mock.Mock(side_effect=Exception)
            ri.process_external()
            # Assess the call for putting the floating IP into Error
            # was performed
            mock_update_fip_status.assert_called_once_with(
                mock.ANY, ri.router_id,
                {fip_id: lib_constants.FLOATINGIP_STATUS_ERROR})

            self.assertEqual(1, ri.iptables_manager._apply.call_count)

    def test_handle_router_snat_rules_distributed_without_snat_manager(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self._set_ri_kwargs(agent, 'foo_router_id', {})
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        ri.iptables_manager = mock.MagicMock()
        ri._is_this_snat_host = mock.Mock(return_value=True)
        ri.get_ex_gw_port = mock.Mock(return_value=None)

        ri._handle_router_snat_rules(None, mock.ANY)
        self.assertIsNone(ri.snat_iptables_manager)
        self.assertFalse(ri.iptables_manager.called)

    def test_handle_router_snat_rules_add_back_jump(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = l3router.RouterInfo(agent, _uuid(), {}, **self.ri_kwargs)
        ri.iptables_manager = mock.MagicMock()
        port = {'fixed_ips': [{'ip_address': '192.168.1.4'}]}

        ri._handle_router_snat_rules(port, "iface")

        nat = ri.iptables_manager.ipv4['nat']
        nat.empty_chain.assert_any_call('snat')
        nat.add_rule.assert_any_call('snat', '-j $float-snat')
        for call in nat.mock_calls:
            name, args, kwargs = call
            if name == 'add_rule':
                self.assertEqual(('snat', '-j $float-snat'), args)
                self.assertEqual({}, kwargs)
                break

    def test_handle_router_snat_rules_add_rules(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = l3router.RouterInfo(agent, _uuid(), {}, **self.ri_kwargs)
        ex_gw_port = {'fixed_ips': [{'ip_address': '192.168.1.4'}]}
        ri.router = {'distributed': False}
        ri._handle_router_snat_rules(ex_gw_port, "iface")

        nat_rules = list(map(str, ri.iptables_manager.ipv4['nat'].rules))
        wrap_name = ri.iptables_manager.wrap_name

        jump_float_rule = "-A %s-snat -j %s-float-snat" % (wrap_name,
                                                           wrap_name)
        snat_rule1 = ("-A %s-snat -o iface -j SNAT --to-source %s "
                      "--random-fully") % (
            wrap_name, ex_gw_port['fixed_ips'][0]['ip_address'])
        snat_rule2 = ("-A %s-snat -m mark ! --mark 0x2/%s "
                      "-m conntrack --ctstate DNAT "
                      "-j SNAT --to-source %s --random-fully") % (
            wrap_name, lib_constants.ROUTER_MARK_MASK,
            ex_gw_port['fixed_ips'][0]['ip_address'])

        self.assertIn(jump_float_rule, nat_rules)

        self.assertIn(snat_rule1, nat_rules)
        self.assertIn(snat_rule2, nat_rules)
        self.assertThat(nat_rules.index(jump_float_rule),
                        matchers.LessThan(nat_rules.index(snat_rule1)))

        mangle_rules = list(map(str, ri.iptables_manager.ipv4['mangle'].rules))
        mangle_rule = ("-A %s-mark -i iface "
                       "-j MARK --set-xmark 0x2/%s" %
                       (wrap_name, lib_constants.ROUTER_MARK_MASK))
        self.assertIn(mangle_rule, mangle_rules)

    def test_process_router_delete_stale_internal_devices(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        stale_devlist = [l3_test_common.FakeDev('qr-a1b2c3d4-e5'),
                         l3_test_common.FakeDev('qr-b2c3d4e5-f6')]
        stale_devnames = [dev.name for dev in stale_devlist]

        get_devices_return = []
        get_devices_return.extend(stale_devlist)
        self.mock_ip.get_devices.return_value = get_devices_return

        router = l3_test_common.prepare_router_data(enable_snat=True,
                                                    num_internal_ports=1)
        ri = l3router.RouterInfo(agent, router['id'], router, **self.ri_kwargs)

        internal_ports = ri.router.get(lib_constants.INTERFACE_KEY, [])
        self.assertEqual(1, len(internal_ports))
        internal_port = internal_ports[0]

        with mock.patch.object(ri, 'internal_network_removed'
                               ) as internal_network_removed,\
                mock.patch.object(ri, 'internal_network_added'
                                  ) as internal_network_added,\
                mock.patch.object(ri, 'external_gateway_removed'
                                  ) as external_gateway_removed,\
                mock.patch.object(ri, 'external_gateway_added'
                                  ) as external_gateway_added:

            ri.process()

            self.assertEqual(1, external_gateway_added.call_count)
            self.assertFalse(external_gateway_removed.called)
            self.assertFalse(internal_network_removed.called)
            internal_network_added.assert_called_once_with(internal_port)
            self.assertEqual(len(stale_devnames),
                             self.mock_driver.unplug.call_count)
            calls = [mock.call(stale_devname,
                               namespace=ri.ns_name,
                               prefix=namespaces.INTERNAL_DEV_PREFIX)
                     for stale_devname in stale_devnames]
            self.mock_driver.unplug.assert_has_calls(calls, any_order=True)

    def test_process_router_delete_stale_external_devices(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        stale_devlist = [l3_test_common.FakeDev('qg-a1b2c3d4-e5')]
        stale_devnames = [dev.name for dev in stale_devlist]

        router = l3_test_common.prepare_router_data(enable_snat=True,
                                                    num_internal_ports=1)
        del router['gw_port']
        ri = l3router.RouterInfo(agent, router['id'], router, **self.ri_kwargs)

        self.mock_ip.get_devices.return_value = stale_devlist

        ri.process()

        self.mock_driver.unplug.assert_called_with(
            stale_devnames[0],
            namespace=ri.ns_name,
            prefix=namespaces.EXTERNAL_DEV_PREFIX)

    def test_process_dvr_router_delete_stale_external_devices(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        stale_devlist = [l3_test_common.FakeDev('qg-a1b2c3d4-e5')]
        stale_devnames = [dev.name for dev in stale_devlist]

        router = l3_test_common.prepare_router_data(enable_snat=True,
                                                    num_internal_ports=1)
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        ri.snat_iptables_manager = iptables_manager.IptablesManager(
            namespace=ri.snat_namespace.name, use_ipv6=ri.use_ipv6)
        self.mock_ip.get_devices.return_value = stale_devlist

        ri.process()

        self.mock_driver.unplug.assert_called_with(
            stale_devnames[0],
            namespace=ri.snat_namespace.name,
            prefix=namespaces.EXTERNAL_DEV_PREFIX)

    def test_process_dvr_router_delete_stale_external_devices_no_snat_ns(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data(enable_gw=False,
                                                    num_internal_ports=1)
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        self.mock_ip.netns.exists.return_value = False
        ri._delete_stale_external_devices('qg-a1b2c3d4-e5')
        self.assertFalse(self.mock_ip.get_devices.called)

    def test_router_deleted(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent._queue = mock.Mock()
        agent.router_deleted(None, FAKE_ID)
        self.assertEqual(1, agent._queue.add.call_count)

    def test_routers_updated(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent._queue = mock.Mock()
        agent.routers_updated(None, [FAKE_ID])
        self.assertEqual(1, agent._queue.add.call_count)

    def test_removed_from_agent(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent._queue = mock.Mock()
        agent.router_removed_from_agent(None, {'router_id': FAKE_ID})
        self.assertEqual(1, agent._queue.add.call_count)

    def test_added_to_agent(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent._queue = mock.Mock()
        agent.router_added_to_agent(None, [FAKE_ID])
        self.assertEqual(1, agent._queue.add.call_count)

    def test_network_update_not_called(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent._queue = mock.Mock()
        network = {'id': _uuid()}
        agent.network_update(None, network=network)
        self.assertFalse(agent._queue.add.called)

    def test_network_update(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent._process_added_router(router)
        ri = l3router.RouterInfo(agent, router['id'],
                                 router, **self.ri_kwargs)
        internal_ports = ri.router.get(lib_constants.INTERFACE_KEY, [])
        network_id = internal_ports[0]['network_id']
        agent._queue = mock.Mock()
        network = {'id': network_id}
        agent.network_update(None, network=network)
        self.assertEqual(1, agent._queue.add.call_count)

    def test_create_router_namespace(self):
        self.mock_ip.ensure_namespace.return_value = self.mock_ip
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ns = namespaces.Namespace(
            'qrouter-bar', self.conf, agent.driver, agent.use_ipv6)
        ns.create()

        calls = [mock.call(['sysctl', '-w', 'net.ipv4.ip_forward=1']),
                 mock.call(['sysctl', '-w', 'net.ipv4.conf.all.arp_ignore=1']),
                 mock.call(
                     ['sysctl', '-w', 'net.ipv4.conf.all.arp_announce=2'])]
        if agent.use_ipv6:
            calls.append(mock.call(
                ['sysctl', '-w', 'net.ipv6.conf.all.forwarding=1']))

        self.mock_ip.netns.execute.assert_has_calls(calls)

    def test_destroy_namespace(self):
        namespace = 'qrouter-bar'

        self.list_network_namespaces.return_value = [namespace]
        self.mock_ip.get_devices.return_value = [
            l3_test_common.FakeDev('qr-aaaa'),
            l3_test_common.FakeDev('rfp-aaaa')]

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        ns = namespaces.RouterNamespace(
            'bar', self.conf, agent.driver, agent.use_ipv6)
        ns.create()

        ns.delete()
        self.mock_driver.unplug.assert_called_once_with('qr-aaaa',
                                                        prefix='qr-',
                                                        namespace='qrouter'
                                                        '-bar')
        self.mock_ip.del_veth.assert_called_once_with('rfp-aaaa')

    def test_destroy_router_namespace(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ns = namespaces.Namespace(
            'qrouter-bar', self.conf, agent.driver, agent.use_ipv6)
        ns.create()
        ns.delete()
        self.mock_ip.netns.delete.assert_called_once_with("qrouter-bar")

    def test_destroy_snat_namespace(self):
        namespace = 'snat-bar'

        self.list_network_namespaces.return_value = [namespace]
        self.mock_ip.get_devices.return_value = [
            l3_test_common.FakeDev('qg-aaaa'),
            l3_test_common.FakeDev('sg-aaaa')]

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        ns = dvr_snat_ns.SnatNamespace(
            'bar', self.conf, agent.driver, agent.use_ipv6)
        ns.create()

        ns.delete()
        calls = [mock.call('qg-aaaa',
                           namespace=namespace,
                           prefix=namespaces.EXTERNAL_DEV_PREFIX),
                 mock.call('sg-aaaa',
                           namespace=namespace,
                           prefix=lib_constants.SNAT_INT_DEV_PREFIX)]
        self.mock_driver.unplug.assert_has_calls(calls, any_order=True)

    def _configure_metadata_proxy(self, enableflag=True):
        if not enableflag:
            self.conf.set_override('enable_metadata_proxy', False)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router_id = _uuid()
        router = {'id': router_id,
                  'external_gateway_info': {},
                  'routes': [],
                  'distributed': False}
        driver = metadata_driver.MetadataDriver
        with mock.patch.object(
                driver, 'destroy_monitored_metadata_proxy') as destroy_proxy:
            with mock.patch.object(
                    driver, 'spawn_monitored_metadata_proxy') as spawn_proxy:
                agent._process_added_router(router)
                if enableflag:
                    spawn_proxy.assert_called_with(
                        mock.ANY,
                        mock.ANY,
                        self.conf.metadata_port,
                        mock.ANY,
                        router_id=router_id
                    )
                else:
                    self.assertFalse(spawn_proxy.call_count)
                agent._safe_router_removed(router_id)
                if enableflag:
                    destroy_proxy.assert_called_with(mock.ANY,
                                                     router_id,
                                                     mock.ANY,
                                                     'qrouter-' + router_id)
                else:
                    self.assertFalse(destroy_proxy.call_count)

    def test_enable_metadata_proxy(self):
        self._configure_metadata_proxy()

    def test_disable_metadata_proxy_spawn(self):
        self._configure_metadata_proxy(enableflag=False)

    def _test_process_routers_update_rpc_timeout(self, ext_net_call=False,
                                                 ext_net_call_failed=False):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.fullsync = False
        agent._process_router_if_compatible = mock.Mock()
        router_id = _uuid()
        router = {'id': router_id,
                  'external_gateway_info': {'network_id': 'aaa'}}
        self.plugin_api.get_routers.return_value = [router]
        if ext_net_call_failed:
            agent._process_router_if_compatible.side_effect = (
                oslo_messaging.MessagingTimeout)
        agent._queue = mock.Mock()
        agent._resync_router = mock.Mock()
        update = mock.Mock()
        update.id = router_id
        update.resource = None
        agent._queue.each_update_to_next_resource.side_effect = [
            [(None, update)]]
        agent._process_router_update()
        self.assertFalse(agent.fullsync)
        self.assertEqual(ext_net_call,
                         agent._process_router_if_compatible.called)
        agent._resync_router.assert_called_with(update)

    def test_process_routers_update_rpc_timeout_on_get_routers(self):
        self.plugin_api.get_routers.side_effect = (
            oslo_messaging.MessagingTimeout)
        self._test_process_routers_update_rpc_timeout()

    def test_process_routers_update_resyncs_failed_router(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router_id = _uuid()
        router = {'id': router_id}

        # Attempting to configure the router will fail
        agent._process_router_if_compatible = mock.MagicMock()
        agent._process_router_if_compatible.side_effect = RuntimeError()

        # Queue an update from a full sync
        update = resource_processing_queue.ResourceUpdate(
            router_id,
            l3_agent.PRIORITY_SYNC_ROUTERS_TASK,
            resource=router,
            timestamp=timeutils.utcnow())
        agent._queue.add(update)
        agent._process_router_update()

        # The update contained the router object, get_routers won't be called
        self.assertFalse(agent.plugin_rpc.get_routers.called)

        # The update failed, assert that get_routers was called
        agent._process_router_update()
        self.assertTrue(agent.plugin_rpc.get_routers.called)

    def test_process_routers_update_rpc_timeout_on_get_ext_net(self):
        self._test_process_routers_update_rpc_timeout(ext_net_call=True,
                                                      ext_net_call_failed=True)

    def test_process_routers_update_router_update(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent._queue = mock.Mock()
        update = mock.Mock()
        update.resource = None
        update.action = l3_agent.ADD_UPDATE_ROUTER
        router_info = mock.MagicMock()
        agent.router_info[update.id] = router_info
        router_processor = mock.Mock()
        agent._queue.each_update_to_next_resource.side_effect = [
            [(router_processor, update)]]
        agent._resync_router = mock.Mock()
        agent._safe_router_removed = mock.Mock()
        agent.plugin_rpc = mock.MagicMock()
        agent.plugin_rpc.get_routers.side_effect = (
            Exception("Failed to get router info"))
        # start test
        agent._process_router_update()
        router_info.delete.assert_not_called()
        self.assertFalse(router_info.delete.called)
        self.assertTrue(agent.router_info)
        self.assertTrue(agent._resync_router.called)
        self.assertFalse(agent._safe_router_removed.called)

    def _test_process_routers_update_router_deleted(self,
                                                    error=False):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent._queue = mock.Mock()
        update = mock.Mock()
        update.resource = None
        update.action = l3_agent.DELETE_ROUTER
        router_info = mock.MagicMock()
        agent.router_info[update.id] = router_info
        router_processor = mock.Mock()
        agent._queue.each_update_to_next_resource.side_effect = [
            [(router_processor, update)]]
        agent._resync_router = mock.Mock()
        agent._safe_router_removed = mock.Mock()
        if error:
            agent._safe_router_removed.return_value = False
        agent._process_router_update()
        if error:
            self.assertFalse(router_processor.fetched_and_processed.called)
            agent._resync_router.assert_called_with(update)
            self.assertTrue(agent._safe_router_removed.called)
        else:
            router_info.delete.assert_not_called()
            self.assertFalse(router_info.delete.called)
            self.assertTrue(agent.router_info)
            self.assertFalse(agent._resync_router.called)
            router_processor.fetched_and_processed.assert_called_once_with(
                update.timestamp)
            self.assertTrue(agent._safe_router_removed.called)

    def test_process_routers_update_router_deleted_success(self):
        self._test_process_routers_update_router_deleted()

    def test_process_routers_update_router_deleted_error(self):
        self._test_process_routers_update_router_deleted(error=True)

    def test_process_routers_if_compatible(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = {'id': _uuid()}
        related_router = {'id': _uuid()}
        routers = [router, related_router]
        self.plugin_api.get_routers.return_value = routers
        update = resource_processing_queue.ResourceUpdate(
            router['id'], l3_agent.PRIORITY_RPC, resource=router)

        events_queue = []

        def add_mock(update):
            events_queue.append(update)

        agent._queue = mock.Mock()
        agent._queue.add.side_effect = add_mock

        with mock.patch.object(
            agent, "_process_router_if_compatible"
        ) as process_router_if_compatible, mock.patch.object(
            agent, "_safe_router_removed"
        ) as safe_router_removed:
            self.assertTrue(
                agent._process_routers_if_compatible(routers, update))
            process_router_if_compatible.assert_called_once_with(
                router)
            safe_router_removed.assert_not_called()
            self.assertEqual(1, len(events_queue))
            self.assertEqual(related_router['id'], events_queue[0].id)
            self.assertEqual(l3_agent.PRIORITY_RELATED_ROUTER,
                             events_queue[0].priority)

    def test_process_dvr_routers_ha_on_update_when_router_unbound(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.conf.agent_mode = 'dvr_snat'
        router = mock.Mock()
        router.id = '1234'
        router.distributed = True
        router.ha = True
        router_info = mock.MagicMock()

        def mock_get(name):
            if name == 'ha':
                return router.ha
            if name == 'distributed':
                return router.distributed
            return mock.Mock()

        router_info.router.get.side_effect = mock_get

        agent.router_info[router.id] = router_info
        updated_router = {'id': '1234',
                          'distributed': True,
                          'ha': True,
                          'external_gateway_info': {},
                          'routes': [],
                          'admin_state_up': True}

        self.plugin_api.get_routers.return_value = [updated_router]
        update = resource_processing_queue.ResourceUpdate(
            updated_router['id'], l3_agent.PRIORITY_RPC,
            resource=updated_router)

        with mock.patch.object(agent,
                               "_safe_router_removed"
                               ) as router_remove,\
            mock.patch.object(agent,
                              "_process_added_router"
                              ) as add_router:
            agent._process_routers_if_compatible([updated_router], update)
            router_remove.assert_called_once_with(updated_router['id'])
            add_router.assert_called_once_with(updated_router)

    def test_process_dvr_routers_ha_on_update_without_ha_interface(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.conf.agent_mode = 'dvr_snat'
        router = mock.Mock()
        router.id = '1234'
        router.distributed = True
        router._ha_interface = True
        router.ha = True
        router_info = mock.MagicMock()

        def mock_get(name):
            if name == 'ha':
                return router.ha
            if name == 'distributed':
                return router.distributed
            return mock.Mock()

        router_info.router.get.side_effect = mock_get

        agent.router_info[router.id] = router_info
        updated_router = {'id': '1234',
                          'distributed': True, 'ha': True,
                          'external_gateway_info': {}, 'routes': [],
                          'admin_state_up': True}

        self.plugin_api.get_routers.return_value = [updated_router]
        update = resource_processing_queue.ResourceUpdate(
            updated_router['id'], l3_agent.PRIORITY_RPC,
            resource=updated_router)

        with mock.patch.object(agent,
                               "_safe_router_removed"
                               ) as router_remove,\
            mock.patch.object(agent,
                              "_process_added_router"
                              ) as add_router:
            agent._process_routers_if_compatible([updated_router], update)
            router_remove.assert_called_once_with(updated_router['id'])
            add_router.assert_called_once_with(updated_router)

    def test_process_routers_if_compatible_error(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = {'id': _uuid()}
        self.plugin_api.get_routers.return_value = [router]
        update = resource_processing_queue.ResourceUpdate(
            router['id'], l3_agent.PRIORITY_RPC, resource=router)

        with mock.patch.object(
            agent, "_process_router_if_compatible",
            side_effect=Exception(
                "Test failure during _process_routers_if_compatible")
        ) as process_router_if_compatible, mock.patch.object(
            agent, "_safe_router_removed"
        ) as safe_router_removed:
            self.assertFalse(
                agent._process_routers_if_compatible([router], update))
            process_router_if_compatible.assert_called_once_with(
                router)
            safe_router_removed.assert_not_called()

    def test_process_ha_dvr_router_if_compatible_no_ha_interface(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.conf.agent_mode = 'dvr_snat'
        router = {'id': _uuid(),
                  'distributed': True, 'ha': True,
                  'external_gateway_info': {}, 'routes': [],
                  'admin_state_up': True}
        with mock.patch.object(agent, 'check_ha_state_for_router') as chsfr:
            agent._process_router_if_compatible(router)
            self.assertIn(router['id'], agent.router_info)
            self.assertFalse(chsfr.called)

    def test_process_router_if_compatible(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        router = {'id': _uuid(),
                  'routes': [],
                  'admin_state_up': True,
                  'external_gateway_info': {'network_id': 'aaa'}}

        agent._process_router_if_compatible(router)
        self.assertIn(router['id'], agent.router_info)

    def test_process_router_if_compatible_type_match(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        router = {'id': _uuid(),
                  'routes': [],
                  'admin_state_up': True,
                  'ha': False, 'distributed': False,
                  'external_gateway_info': {'network_id': 'aaa'}}

        ri = mock.Mock(router=router)
        agent.router_info[router['id']] = ri
        with mock.patch.object(agent, "_create_router") as create_router_mock:
            agent._process_router_if_compatible(router)
        create_router_mock.assert_not_called()
        self.assertIn(router['id'], agent.router_info)
        self.assertFalse(agent.router_info[router['id']].router['ha'])
        self.assertFalse(agent.router_info[router['id']].router['distributed'])

    def test_process_router_if_compatible_type_changed(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        router = {'id': _uuid(),
                  'routes': [],
                  'admin_state_up': True,
                  'revision_number': 1,
                  'ha': True, 'distributed': False,
                  'external_gateway_info': {'network_id': 'aaa'}}

        ri = mock.Mock(router=router)
        agent.router_info[router['id']] = ri
        new_router = copy.deepcopy(router)
        new_router['ha'] = False
        with mock.patch.object(agent, "_create_router") as create_router_mock:
            agent._process_router_if_compatible(new_router)
        create_router_mock.assert_called_once_with(
            new_router['id'], new_router)
        self.assertIn(router['id'], agent.router_info)
        self.assertFalse(agent.router_info[router['id']].router['ha'])
        self.assertFalse(agent.router_info[router['id']].router['distributed'])

    def test_nonexistent_interface_driver(self):
        self.conf.set_override('interface_driver', None)
        self.assertRaises(SystemExit, l3_agent.L3NATAgent,
                          HOSTNAME, self.conf)

        self.conf.set_override('interface_driver', 'wrong.driver')
        self.assertRaises(SystemExit, l3_agent.L3NATAgent,
                          HOSTNAME, self.conf)

    @mock.patch.object(namespaces.RouterNamespace, 'delete')
    @mock.patch.object(dvr_snat_ns.SnatNamespace, 'delete')
    def _cleanup_namespace_test(self,
                                stale_namespace_list,
                                router_list,
                                other_namespaces,
                                mock_snat_ns,
                                mock_router_ns):

        good_namespace_list = [namespaces.NS_PREFIX + r['id']
                               for r in router_list]
        good_namespace_list += [dvr_snat_ns.SNAT_NS_PREFIX + r['id']
                                for r in router_list]
        self.list_network_namespaces.return_value = (stale_namespace_list +
                                                     good_namespace_list +
                                                     other_namespaces)

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        self.assertTrue(agent.namespaces_manager._clean_stale)

        pm = self.external_process.return_value
        pm.reset_mock()

        with agent.namespaces_manager as ns_manager:
            for r in router_list:
                ns_manager.keep_router(r['id'])
        qrouters = [n for n in stale_namespace_list
                    if n.startswith(namespaces.NS_PREFIX)]
        self.assertEqual(len(qrouters), mock_router_ns.call_count)
        self.assertEqual(
            len(stale_namespace_list) - len(qrouters),
            mock_snat_ns.call_count)

        self.assertFalse(agent.namespaces_manager._clean_stale)

    def test_cleanup_namespace(self):
        stale_namespaces = [namespaces.NS_PREFIX + 'foo',
                            namespaces.NS_PREFIX + 'bar',
                            dvr_snat_ns.SNAT_NS_PREFIX + 'foo']
        other_namespaces = ['unknown']

        self._cleanup_namespace_test(stale_namespaces,
                                     [],
                                     other_namespaces)

    def test_cleanup_namespace_with_registered_router_ids(self):
        stale_namespaces = [namespaces.NS_PREFIX + 'cccc',
                            namespaces.NS_PREFIX + 'eeeee',
                            dvr_snat_ns.SNAT_NS_PREFIX + 'fffff']
        router_list = [{'id': 'foo', 'distributed': False},
                       {'id': 'aaaa', 'distributed': False}]
        other_namespaces = ['qdhcp-aabbcc', 'unknown']

        self._cleanup_namespace_test(stale_namespaces,
                                     router_list,
                                     other_namespaces)

    def test_create_dvr_gateway(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data()
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)

        port_id = _uuid()
        subnet_id = _uuid()
        dvr_gw_port = {'fixed_ips': [{'ip_address': '20.0.0.30',
                                      'prefixlen': 24,
                                      'subnet_id': subnet_id}],
                       'subnets': [{'id': subnet_id,
                                    'cidr': '20.0.0.0/24',
                                    'gateway_ip': '20.0.0.1'}],
                       'id': port_id,
                       'network_id': _uuid(),
                       'mtu': 1500,
                       'mac_address': 'ca:fe:de:ad:be:ef'}

        interface_name = ri._get_snat_int_device_name(port_id)
        self.device_exists.return_value = False

        with mock.patch.object(ri, 'get_snat_interfaces') as get_interfaces:
            get_interfaces.return_value = self.snat_ports
            ri._create_dvr_gateway(dvr_gw_port, interface_name)

        # check 2 internal ports are plugged
        # check 1 ext-gw-port is plugged
        self.assertEqual(3, self.mock_driver.plug.call_count)
        self.assertEqual(3, self.mock_driver.init_router_port.call_count)

    def test_process_address_scope(self):
        router = l3_test_common.prepare_router_data()
        router['distributed'] = True
        router['gw_port_host'] = HOSTNAME

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        ri.get_ex_gw_port = mock.Mock(return_value=None)

        # Make sure the code doesn't crash if ri.snat_iptables_manager is None.
        ri.process_address_scope()

        with mock.patch.object(ri, '_add_address_scope_mark') as mocked_func:
            ri.snat_iptables_manager = iptables_manager.IptablesManager(
                namespace=mock.ANY, use_ipv6=False)
            ri.snat_iptables_manager.defer_apply_off = mock.Mock()

            ri.process_address_scope()
            self.assertEqual(2, mocked_func.call_count)

    def test_get_host_ha_router_count(self):
        self.plugin_api.get_host_ha_router_count.return_value = 1
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.assertEqual(1, agent.ha_router_count)
        self.assertTrue(self.plugin_api.get_host_ha_router_count.called)

    def test_get_host_ha_router_count_retried(self):
        raise_timeout = oslo_messaging.MessagingTimeout()
        # Raise a timeout the first 2 times it calls
        # get_host_ha_router_count then return 0
        self.plugin_api.get_host_ha_router_count.side_effect = (
            raise_timeout, 0
        )
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        self.assertEqual(0, agent.ha_router_count)

    def test_external_gateway_removed_ext_gw_port_no_fip_ns(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.conf.agent_mode = 'dvr_snat'
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['gw_port_host'] = HOSTNAME
        self.mock_driver.unplug.reset_mock()

        external_net_id = router['gw_port']['network_id']
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        ri.remove_floating_ip = mock.Mock()
        agent._fetch_external_net_id = mock.Mock(return_value=external_net_id)
        ri.ex_gw_port = ri.router['gw_port']
        del ri.router['gw_port']
        ri.external_gateway_added(
            ri.ex_gw_port,
            ri.get_external_device_name(ri.ex_gw_port['id']))
        ri.fip_ns = None
        nat = ri.iptables_manager.ipv4['nat']
        nat.clear_rules_by_tag = mock.Mock()
        nat.add_rule = mock.Mock()

        ri.snat_namespace = mock.Mock()
        ri.external_gateway_removed(
            ri.ex_gw_port,
            ri.get_external_device_name(ri.ex_gw_port['id']))

        self.assertFalse(ri.remove_floating_ip.called)

    @mock.patch.object(os, 'geteuid', return_value=mock.ANY)
    @mock.patch.object(pwd, 'getpwuid')
    def test_spawn_radvd(self, mock_getpwuid, *args):
        router = l3_test_common.prepare_router_data(
            ip_version=lib_constants.IP_VERSION_6)

        conffile = '/fake/radvd.conf'
        pidfile = '/fake/radvd.pid'
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        # we don't want the whole process manager to be mocked to be
        # able to catch execute() calls
        self.external_process_p.stop()
        self.ip_cls_p.stop()

        get_conf_file_name = 'neutron.agent.linux.utils.get_conf_file_name'
        get_pid_file_name = ('neutron.agent.linux.external_process.'
                             'ProcessManager.get_pid_file_name')
        utils_execute = 'neutron.agent.common.utils.execute'

        mock.patch(get_conf_file_name).start().return_value = conffile
        mock.patch(get_pid_file_name).start().return_value = pidfile
        execute = mock.patch(utils_execute).start()

        radvd = ra.DaemonMonitor(
            router['id'],
            namespaces.RouterNamespace._get_ns_name(router['id']),
            agent.process_monitor,
            l3_test_common.FakeDev,
            self.conf)

        test_users = [('', 'stack', '-u stack'),
                      ('neutron', mock.ANY, '-u neutron'),
                      ('root', mock.ANY, None)]
        for radvd_user, os_user, to_check in test_users:
            self.conf.set_override('radvd_user', radvd_user)
            mock_getpwuid.return_value = FakeUser(os_user)
            radvd.enable(router['_interfaces'])
            cmd = execute.call_args[0][0]
            _join = lambda *args: ' '.join(args)
            cmd = _join(*cmd)
            self.assertIn('radvd', cmd)
            self.assertIn(_join('-C', conffile), cmd)
            self.assertIn(_join('-p', pidfile), cmd)
            self.assertIn(_join('-m', 'syslog'), cmd)
            if to_check:
                self.assertIn(to_check, cmd)
            else:
                self.assertNotIn('-u', cmd)

    def test_generate_radvd_mtu_conf(self):
        router = l3_test_common.prepare_router_data()
        ipv6_subnet_modes = [{'ra_mode': lib_constants.IPV6_SLAAC,
                             'address_mode': lib_constants.IPV6_SLAAC}]
        network_mtu = '1446'
        ri = self._process_router_ipv6_subnet_added(router,
                                                    ipv6_subnet_modes,
                                                    None,
                                                    network_mtu)
        # Verify that MTU is advertised
        expected = "AdvLinkMTU 1446"
        ri.radvd._generate_radvd_conf(router[lib_constants.INTERFACE_KEY])
        self.assertIn(expected, self.utils_replace_file.call_args[0][1])

    def test_generate_radvd_conf_other_and_managed_flag(self):
        # expected = {ra_mode: (AdvOtherConfigFlag, AdvManagedFlag), ...}
        expected = {lib_constants.IPV6_SLAAC: (False, False),
                    lib_constants.DHCPV6_STATELESS: (True, False),
                    lib_constants.DHCPV6_STATEFUL: (False, True)}

        modes = [lib_constants.IPV6_SLAAC, lib_constants.DHCPV6_STATELESS,
                 lib_constants.DHCPV6_STATEFUL]
        mode_combos = list(iter_chain(*[[list(combo) for combo in
            iter_combinations(modes, i)] for i in range(1, len(modes) + 1)]))

        for mode_list in mode_combos:
            ipv6_subnet_modes = [{'ra_mode': mode, 'address_mode': mode}
                                 for mode in mode_list]
            router = l3_test_common.prepare_router_data()
            ri = self._process_router_ipv6_subnet_added(router,
                                                        ipv6_subnet_modes)

            ri.radvd._generate_radvd_conf(router[lib_constants.INTERFACE_KEY])

            def assertFlag(flag):
                return (self.assertIn if flag else self.assertNotIn)

            other_flag, managed_flag = (
                    any(expected[mode][0] for mode in mode_list),
                    any(expected[mode][1] for mode in mode_list))

            assertFlag(other_flag)('AdvOtherConfigFlag on;',
                self.utils_replace_file.call_args[0][1])
            assertFlag(managed_flag)('AdvManagedFlag on;',
                self.utils_replace_file.call_args[0][1])

    def test_generate_radvd_intervals(self):
        self.conf.set_override('min_rtr_adv_interval', 22)
        self.conf.set_override('max_rtr_adv_interval', 66)
        router = l3_test_common.prepare_router_data()
        ipv6_subnet_modes = [{'ra_mode': lib_constants.IPV6_SLAAC,
                             'address_mode': lib_constants.IPV6_SLAAC}]
        ri = self._process_router_ipv6_subnet_added(router,
                                                    ipv6_subnet_modes)
        ri.radvd._generate_radvd_conf(router[lib_constants.INTERFACE_KEY])
        self.assertIn("MinRtrAdvInterval 22",
                      self.utils_replace_file.call_args[0][1])
        self.assertIn("MaxRtrAdvInterval 66",
                      self.utils_replace_file.call_args[0][1])

    def test_generate_radvd_rdnss_conf(self):
        router = l3_test_common.prepare_router_data()
        ipv6_subnet_modes = [{'ra_mode': lib_constants.IPV6_SLAAC,
                             'address_mode': lib_constants.IPV6_SLAAC}]
        dns_list = ['fd01:1::100', 'fd01:1::200', 'fd01::300', 'fd01::400']
        ri = self._process_router_ipv6_subnet_added(router,
                                                    ipv6_subnet_modes,
                                                    dns_nameservers=dns_list)
        ri.radvd._generate_radvd_conf(router[lib_constants.INTERFACE_KEY])
        # Verify that radvd configuration file includes RDNSS entries
        expected = "RDNSS  "
        for dns in dns_list[0:ra.MAX_RDNSS_ENTRIES]:
            expected += "%s  " % dns
        self.assertIn(expected, self.utils_replace_file.call_args[0][1])

    def _pd_expected_call_external_process(self, requestor, ri,
                                           enable=True, ha=False):
        expected_calls = []
        if enable:
            expected_calls.append(mock.call(uuid=requestor,
                                            service='dibbler',
                                            default_cmd_callback=mock.ANY,
                                            namespace=ri.ns_name,
                                            conf=mock.ANY,
                                            pid_file=mock.ANY))
            expected_calls.append(mock.call().enable(reload_cfg=False))
        else:
            expected_calls.append(mock.call(uuid=requestor,
                                            service='dibbler',
                                            namespace=ri.ns_name,
                                            conf=mock.ANY,
                                            pid_file=mock.ANY))
            # in the HA switchover case, disable is called without arguments
            if ha:
                expected_calls.append(mock.call().disable())
            else:
                expected_calls.append(mock.call().disable(
                    get_stop_command=mock.ANY))
        return expected_calls

    def _pd_setup_agent_router(self, enable_ha=False):
        router = l3_test_common.prepare_router_data()
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent._router_added(router['id'], router)
        # Make sure radvd monitor is created
        ri = agent.router_info[router['id']]
        ri.iptables_manager.ipv6['mangle'] = mock.MagicMock()
        ri._process_pd_iptables_rules = mock.MagicMock()
        if not ri.radvd:
            ri.radvd = ra.DaemonMonitor(router['id'],
                                        ri.ns_name,
                                        agent.process_monitor,
                                        ri.get_internal_device_name,
                                        self.conf)
        if enable_ha:
            agent.pd.routers[router['id']]['master'] = False
        return agent, router, ri

    def _pd_remove_gw_interface(self, intfs, agent, ri):
        expected_pd_update = {}
        expected_calls = []
        for intf in intfs:
            requestor_id = self._pd_get_requestor_id(intf, ri)
            expected_calls += (self._pd_expected_call_external_process(
                requestor_id, ri, False))
            for subnet in intf['subnets']:
                expected_pd_update[subnet['id']] = (
                    lib_constants.PROVISIONAL_IPV6_PD_PREFIX)

        # Implement the prefix update notifier
        # Keep track of the updated prefix
        self.pd_update = {}

        def pd_notifier(context, prefix_update):
            self.pd_update = prefix_update
            for subnet_id, prefix in prefix_update.items():
                for intf in intfs:
                    for subnet in intf['subnets']:
                        if subnet['id'] == subnet_id:
                            # Update the prefix
                            subnet['cidr'] = prefix
                            break

        # Remove the gateway interface
        agent.pd.notifier = pd_notifier
        agent.pd.remove_gw_interface(ri.router['id'])

        self._pd_assert_dibbler_calls(expected_calls,
            self.external_process.mock_calls[-len(expected_calls):])
        self.assertEqual(expected_pd_update, self.pd_update)

    def _pd_remove_interfaces(self, intfs, agent, ri):
        expected_pd_update = []
        expected_calls = []
        for intf in intfs:
            # Remove the router interface
            ri.router[lib_constants.INTERFACE_KEY].remove(intf)
            requestor_id = self._pd_get_requestor_id(intf, ri)
            expected_calls += (self._pd_expected_call_external_process(
                requestor_id, ri, False))
            for subnet in intf['subnets']:
                expected_pd_update += [{subnet['id']:
                    lib_constants.PROVISIONAL_IPV6_PD_PREFIX}]

        # Implement the prefix update notifier
        # Keep track of the updated prefix
        self.pd_update = []

        def pd_notifier(context, prefix_update):
            self.pd_update.append(prefix_update)
            for intf in intfs:
                for subnet in intf['subnets']:
                    if subnet['id'] in prefix_update:
                        # Update the prefix
                        subnet['cidr'] = prefix_update[subnet['id']]

        # Process the router for removed interfaces
        agent.pd.notifier = pd_notifier
        ri.process()

        # The number of external process calls takes radvd into account.
        # This is because there is no ipv6 interface any more after removing
        # the interfaces, and radvd will be killed because of that
        self._pd_assert_dibbler_calls(expected_calls,
            self.external_process.mock_calls[-len(expected_calls) - 2:])
        self._pd_assert_radvd_calls(ri, False)
        self.assertEqual(expected_pd_update, self.pd_update)

    def _pd_get_requestor_id(self, intf, ri):
        ifname = ri.get_internal_device_name(intf['id'])
        for subnet in intf['subnets']:
            return dibbler.PDDibbler(ri.router['id'],
                                     subnet['id'], ifname).requestor_id

    def _pd_assert_dibbler_calls(self, expected, actual):
        '''Check the external process calls for dibbler are expected

        in the case of multiple pd-enabled router ports, the exact sequence
        of these calls are not deterministic. It's known, though, that each
        external_process call is followed with either an enable() or disable()
        '''

        num_ext_calls = len(expected) // 2
        expected_ext_calls = []
        actual_ext_calls = []
        expected_action_calls = []
        actual_action_calls = []
        for c in range(num_ext_calls):
            expected_ext_calls.append(expected[c * 2])
            actual_ext_calls.append(actual[c * 2])
            expected_action_calls.append(expected[c * 2 + 1])
            actual_action_calls.append(actual[c * 2 + 1])

        self.assertEqual(expected_action_calls, actual_action_calls)
        for exp in expected_ext_calls:
            for act in actual_ext_calls:
                if exp == act:
                    break
            else:
                msg = "Unexpected dibbler external process call."
                self.fail(msg)

    def _pd_assert_radvd_calls(self, ri, enable=True):
        exp_calls = self._radvd_expected_call_external_process(ri, enable)
        self.assertEqual(exp_calls,
                         self.external_process.mock_calls[-len(exp_calls):])

    def _pd_assert_update_subnet_calls(self, router_id, intfs,
                                       mock_pd_update_subnet):
        for intf in intfs:
            mock_pd_update_subnet.assert_any_call(router_id,
                intf['subnets'][0]['id'],
                intf['subnets'][0]['cidr'])

    def _pd_get_prefixes(self, agent, ri,
                         existing_intfs, new_intfs, mock_get_prefix):
        # First generate the prefixes that will be used for each interface
        prefixes = {}
        expected_pd_update = {}
        expected_calls = []
        last_prefix = ''
        for ifno, intf in enumerate(existing_intfs + new_intfs):
            requestor_id = self._pd_get_requestor_id(intf, ri)
            prefixes[requestor_id] = "2001:db8:%d::/64" % ifno
            last_prefix = prefixes[requestor_id]
            if intf in new_intfs:
                subnet_id = (intf['subnets'][0]['id'] if intf['subnets']
                             else None)
                expected_pd_update[subnet_id] = prefixes[requestor_id]
                expected_calls += (
                    self._pd_expected_call_external_process(requestor_id, ri))

        # Implement the prefix update notifier
        # Keep track of the updated prefix
        self.pd_update = {}

        def pd_notifier(context, prefix_update):
            self.pd_update = prefix_update
            for subnet_id, prefix in prefix_update.items():
                gateway_ip = '%s1' % netaddr.IPNetwork(prefix).network
                for intf in new_intfs:
                    for fip in intf['fixed_ips']:
                        if fip['subnet_id'] == subnet_id:
                            fip['ip_address'] = gateway_ip
                    for subnet in intf['subnets']:
                        if subnet['id'] == subnet_id:
                            # Update the prefix
                            subnet['cidr'] = prefix
                            subnet['gateway_ip'] = gateway_ip
                            break

        # Start the dibbler client
        agent.pd.notifier = pd_notifier
        agent.pd.process_prefix_update()

        # Get the prefix and check that the neutron server is notified
        def get_prefix(pdo):
            key = '%s:%s:%s' % (pdo.router_id, pdo.subnet_id, pdo.ri_ifname)
            return prefixes[key]
        mock_get_prefix.side_effect = get_prefix
        agent.pd.process_prefix_update()

        # Make sure that the updated prefixes are expected
        self._pd_assert_dibbler_calls(expected_calls,
             self.external_process.mock_calls[-len(expected_calls):])
        self.assertEqual(expected_pd_update, self.pd_update)

        return last_prefix

    def _pd_verify_update_results(self, ri, pd_intfs, mock_pd_update_subnet):
        # verify router port initialized
        for intf in pd_intfs:
            self.mock_driver.init_router_port.assert_any_call(
                ri.get_internal_device_name(intf['id']),
                ip_cidrs=l3router.common_utils.fixed_ip_cidrs(
                    intf['fixed_ips']),
                namespace=ri.ns_name)
        # verify that subnet is updated in PD
        self._pd_assert_update_subnet_calls(ri.router['id'], pd_intfs,
                                            mock_pd_update_subnet)

        # Check that radvd is started
        self._pd_assert_radvd_calls(ri)

    def _pd_add_gw_interface(self, agent, ri):
        gw_ifname = ri.get_external_device_name(ri.router['gw_port']['id'])
        agent.pd.add_gw_interface(ri.router['id'], gw_ifname)

    @mock.patch.object(pd.PrefixDelegation, 'update_subnet')
    @mock.patch.object(dibbler.PDDibbler, 'get_prefix', autospec=True)
    @mock.patch.object(dibbler.os, 'getpid', return_value=1234)
    @mock.patch.object(pd.PrefixDelegation, '_is_lla_active',
                       return_value=True)
    @mock.patch.object(dibbler.os, 'chmod')
    @mock.patch.object(dibbler.shutil, 'rmtree')
    @mock.patch.object(pd.PrefixDelegation, '_get_sync_data')
    def test_pd_have_subnet(self, mock1, mock2, mock3, mock4,
                            mock_getpid, mock_get_prefix,
                            mock_pd_update_subnet):
        '''Add one pd-enabled subnet that has already been assigned
        '''
        prefix = '2001:db8:10::/64'

        # Initial setup
        agent, router, ri = self._pd_setup_agent_router()

        # Create one pd-enabled subnet and add router interface
        l3_test_common.router_append_pd_enabled_subnet(router, prefix=prefix)
        ri.process()

        pd_intfs = l3_test_common.get_assigned_pd_interfaces(router)
        subnet_id = pd_intfs[0]['subnets'][0]['id']

        # Check that _process_pd_iptables_rules() is called correctly
        self.assertEqual({subnet_id: prefix}, ri.pd_subnets)
        ri._process_pd_iptables_rules.assert_called_once_with(prefix,
                                                              subnet_id)

    @mock.patch.object(pd.PrefixDelegation, 'update_subnet')
    @mock.patch.object(dibbler.PDDibbler, 'get_prefix', autospec=True)
    @mock.patch.object(dibbler.os, 'getpid', return_value=1234)
    @mock.patch.object(pd.PrefixDelegation, '_is_lla_active',
                       return_value=True)
    @mock.patch.object(dibbler.os, 'chmod')
    @mock.patch.object(dibbler.shutil, 'rmtree')
    @mock.patch.object(pd.PrefixDelegation, '_get_sync_data')
    def test_pd_add_remove_subnet(self, mock1, mock2, mock3, mock4,
                                  mock_getpid, mock_get_prefix,
                                  mock_pd_update_subnet):
        '''Add and remove one pd-enabled subnet
        Remove the interface by deleting it from the router
        '''
        # Initial setup
        agent, router, ri = self._pd_setup_agent_router()

        # Create one pd-enabled subnet and add router interface
        l3_test_common.router_append_pd_enabled_subnet(router)
        ri.process()

        # Provisional PD prefix on startup, so nothing cached
        self.assertEqual({}, ri.pd_subnets)

        # No client should be started since there is no gateway port
        self.assertFalse(self.external_process.call_count)
        self.assertFalse(mock_get_prefix.call_count)

        # Add the gateway interface
        self._pd_add_gw_interface(agent, ri)

        update_router = copy.deepcopy(router)
        pd_intfs = l3_test_common.get_unassigned_pd_interfaces(update_router)
        subnet_id = pd_intfs[0]['subnets'][0]['id']

        # Get one prefix
        prefix = self._pd_get_prefixes(agent, ri, [],
                                       pd_intfs, mock_get_prefix)

        # Update the router with the new prefix
        ri.router = update_router
        ri.process()

        self._pd_verify_update_results(ri, pd_intfs, mock_pd_update_subnet)

        # Check that _process_pd_iptables_rules() is called correctly
        self.assertEqual({subnet_id: prefix}, ri.pd_subnets)
        ri._process_pd_iptables_rules.assert_called_once_with(prefix,
                                                              subnet_id)

        # Now remove the interface
        self._pd_remove_interfaces(pd_intfs, agent, ri)
        self.assertEqual({}, ri.pd_subnets)

    @mock.patch.object(pd.PrefixDelegation, 'update_subnet')
    @mock.patch.object(dibbler.PDDibbler, 'get_prefix', autospec=True)
    @mock.patch.object(dibbler.os, 'getpid', return_value=1234)
    @mock.patch.object(pd.PrefixDelegation, '_is_lla_active',
                       return_value=True)
    @mock.patch.object(dibbler.os, 'chmod')
    @mock.patch.object(dibbler.shutil, 'rmtree')
    @mock.patch.object(pd.PrefixDelegation, '_get_sync_data')
    def test_pd_remove_gateway(self, mock1, mock2, mock3, mock4,
                               mock_getpid, mock_get_prefix,
                               mock_pd_update_subnet):
        '''Add one pd-enabled subnet and remove the gateway port
        Remove the gateway port and check the prefix is removed
        '''
        # Initial setup
        agent, router, ri = self._pd_setup_agent_router()

        # Create one pd-enabled subnet and add router interface
        l3_test_common.router_append_pd_enabled_subnet(router)
        ri.process()

        # Add the gateway interface
        self._pd_add_gw_interface(agent, ri)

        update_router = copy.deepcopy(router)
        pd_intfs = l3_test_common.get_unassigned_pd_interfaces(update_router)

        # Get one prefix
        self._pd_get_prefixes(agent, ri, [], pd_intfs, mock_get_prefix)

        # Update the router with the new prefix
        ri.router = update_router
        ri.process()

        self._pd_verify_update_results(ri, pd_intfs, mock_pd_update_subnet)

        # Now remove the gw interface
        self._pd_remove_gw_interface(pd_intfs, agent, ri)

    @mock.patch.object(pd.PrefixDelegation, 'update_subnet')
    @mock.patch.object(dibbler.PDDibbler, 'get_prefix', autospec=True)
    @mock.patch.object(dibbler.os, 'getpid', return_value=1234)
    @mock.patch.object(pd.PrefixDelegation, '_is_lla_active',
                       return_value=True)
    @mock.patch.object(dibbler.os, 'chmod')
    @mock.patch.object(dibbler.shutil, 'rmtree')
    @mock.patch.object(pd.PrefixDelegation, '_get_sync_data')
    def test_pd_add_remove_2_subnets(self, mock1, mock2, mock3, mock4,
                                     mock_getpid, mock_get_prefix,
                                     mock_pd_update_subnet):
        '''Add and remove two pd-enabled subnets
        Remove the interfaces by deleting them from the router
        '''
        # Initial setup
        agent, router, ri = self._pd_setup_agent_router()

        # Create 2 pd-enabled subnets and add router interfaces
        l3_test_common.router_append_pd_enabled_subnet(router, count=2)
        ri.process()

        # No client should be started
        self.assertFalse(self.external_process.call_count)
        self.assertFalse(mock_get_prefix.call_count)

        # Add the gateway interface
        self._pd_add_gw_interface(agent, ri)

        update_router = copy.deepcopy(router)
        pd_intfs = l3_test_common.get_unassigned_pd_interfaces(update_router)

        # Get prefixes
        self._pd_get_prefixes(agent, ri, [], pd_intfs, mock_get_prefix)

        # Update the router with the new prefix
        ri.router = update_router
        ri.process()

        self._pd_verify_update_results(ri, pd_intfs, mock_pd_update_subnet)

        # Now remove the interface
        self._pd_remove_interfaces(pd_intfs, agent, ri)

    @mock.patch.object(pd.PrefixDelegation, 'update_subnet')
    @mock.patch.object(dibbler.PDDibbler, 'get_prefix', autospec=True)
    @mock.patch.object(dibbler.os, 'getpid', return_value=1234)
    @mock.patch.object(pd.PrefixDelegation, '_is_lla_active',
                       return_value=True)
    @mock.patch.object(dibbler.os, 'chmod')
    @mock.patch.object(dibbler.shutil, 'rmtree')
    @mock.patch.object(pd.PrefixDelegation, '_get_sync_data')
    def test_pd_remove_gateway_2_subnets(self, mock1, mock2, mock3, mock4,
                                         mock_getpid, mock_get_prefix,
                                         mock_pd_update_subnet):
        '''Add one pd-enabled subnet, followed by adding another one
        Remove the gateway port and check the prefix is removed
        '''
        # Initial setup
        agent, router, ri = self._pd_setup_agent_router()

        # Add the gateway interface
        self._pd_add_gw_interface(agent, ri)

        # Create 1 pd-enabled subnet and add router interface
        l3_test_common.router_append_pd_enabled_subnet(router, count=1)
        ri.process()

        update_router = copy.deepcopy(router)
        pd_intfs = l3_test_common.get_unassigned_pd_interfaces(update_router)

        # Get prefixes
        self._pd_get_prefixes(agent, ri, [], pd_intfs, mock_get_prefix)

        # Update the router with the new prefix
        ri.router = update_router
        ri.process()

        self._pd_verify_update_results(ri, pd_intfs, mock_pd_update_subnet)

        # Now add another interface
        # Create one pd-enabled subnet and add router interface
        l3_test_common.router_append_pd_enabled_subnet(update_router, count=1)
        ri.process()

        update_router_2 = copy.deepcopy(update_router)
        pd_intfs1 = l3_test_common.get_unassigned_pd_interfaces(
            update_router_2)

        # Get prefixes
        self._pd_get_prefixes(agent, ri, pd_intfs, pd_intfs1, mock_get_prefix)

        # Update the router with the new prefix
        ri.router = update_router_2
        ri.process()

        self._pd_verify_update_results(ri, pd_intfs1, mock_pd_update_subnet)

        # Now remove the gw interface
        self._pd_remove_gw_interface(pd_intfs + pd_intfs1, agent, ri)

    @mock.patch.object(l3router.RouterInfo, 'enable_radvd')
    @mock.patch.object(pd.PrefixDelegation, '_add_lla')
    @mock.patch.object(pd.PrefixDelegation, 'update_subnet')
    @mock.patch.object(dibbler.PDDibbler, 'get_prefix', autospec=True)
    @mock.patch.object(dibbler.os, 'getpid', return_value=1234)
    @mock.patch.object(pd.PrefixDelegation, '_is_lla_active',
                       return_value=True)
    @mock.patch.object(dibbler.os, 'chmod')
    @mock.patch.object(dibbler.shutil, 'rmtree')
    @mock.patch.object(pd.PrefixDelegation, '_get_sync_data')
    def test_pd_ha_standby(self, mock1, mock2, mock3, mock4,
                           mock_getpid, mock_get_prefix,
                           mock_pd_update_subnet,
                           mock_add_lla, mock_enable_radvd):
        '''Test HA in the standby router
        The intent is to test the PD code with HA. To avoid unnecessary
        complexities, use the regular router.
        '''
        # Initial setup
        agent, router, ri = self._pd_setup_agent_router(enable_ha=True)

        # Create one pd-enabled subnet and add router interface
        l3_test_common.router_append_pd_enabled_subnet(router)
        self._pd_add_gw_interface(agent, ri)
        ri.process()

        self.assertFalse(mock_add_lla.called)

        # No client should be started since it's standby router
        agent.pd.process_prefix_update()
        self.assertFalse(self.external_process.called)
        self.assertFalse(mock_get_prefix.called)

        update_router = copy.deepcopy(router)
        pd_intfs = l3_test_common.assign_prefix_for_pd_interfaces(
            update_router)

        # Update the router with the new prefix
        ri.router = update_router
        ri.process()

        self._pd_assert_update_subnet_calls(router['id'], pd_intfs,
                                            mock_pd_update_subnet)

        # No client should be started since it's standby router
        agent.pd.process_prefix_update()
        self.assertFalse(self.external_process.called)
        self.assertFalse(mock_get_prefix.called)

    @mock.patch.object(pd.PrefixDelegation, '_add_lla')
    @mock.patch.object(pd.PrefixDelegation, 'update_subnet')
    @mock.patch.object(dibbler.PDDibbler, 'get_prefix', autospec=True)
    @mock.patch.object(dibbler.os, 'getpid', return_value=1234)
    @mock.patch.object(pd.PrefixDelegation, '_is_lla_active',
                       return_value=True)
    @mock.patch.object(dibbler.os, 'chmod')
    @mock.patch.object(dibbler.shutil, 'rmtree')
    @mock.patch.object(pd.PrefixDelegation, '_get_sync_data')
    def test_pd_ha_active(self, mock1, mock2, mock3, mock4,
                          mock_getpid, mock_get_prefix,
                          mock_pd_update_subnet,
                          mock_add_lla):
        '''Test HA in the active router
        The intent is to test the PD code with HA. To avoid unnecessary
        complexities, use the regular router.
        '''
        # Initial setup
        agent, router, ri = self._pd_setup_agent_router(enable_ha=True)

        # Create one pd-enabled subnet and add router interface
        l3_test_common.router_append_pd_enabled_subnet(router)
        self._pd_add_gw_interface(agent, ri)
        ri.process()

        self.assertFalse(mock_add_lla.called)

        # No client should be started since it's standby router
        agent.pd.process_prefix_update()
        self.assertFalse(self.external_process.called)
        self.assertFalse(mock_get_prefix.called)

        update_router = copy.deepcopy(router)
        pd_intfs = l3_test_common.get_unassigned_pd_interfaces(update_router)

        # Turn the router to be active
        agent.pd.process_ha_state(router['id'], True)

        # Get prefixes
        self._pd_get_prefixes(agent, ri, [], pd_intfs, mock_get_prefix)

        # Update the router with the new prefix
        ri.router = update_router
        ri.process()

        self._pd_verify_update_results(ri, pd_intfs, mock_pd_update_subnet)

    @mock.patch.object(pd.PrefixDelegation, 'update_subnet')
    @mock.patch.object(dibbler.PDDibbler, 'get_prefix', autospec=True)
    @mock.patch.object(dibbler.os, 'getpid', return_value=1234)
    @mock.patch.object(pd.PrefixDelegation, '_is_lla_active',
                       return_value=True)
    @mock.patch.object(dibbler.os, 'chmod')
    @mock.patch.object(dibbler.shutil, 'rmtree')
    @mock.patch.object(pd.PrefixDelegation, '_get_sync_data')
    def test_pd_ha_switchover(self, mock1, mock2, mock3, mock4,
                              mock_getpid, mock_get_prefix,
                              mock_pd_update_subnet):
        '''Test HA in the active router
        The intent is to test the PD code with HA. To avoid unnecessary
        complexities, use the regular router.
        '''
        # Initial setup
        agent, router, ri = self._pd_setup_agent_router(enable_ha=True)

        # Turn the router to be active
        agent.pd.process_ha_state(router['id'], True)

        # Create one pd-enabled subnet and add router interface
        l3_test_common.router_append_pd_enabled_subnet(router)
        self._pd_add_gw_interface(agent, ri)
        ri.process()

        update_router = copy.deepcopy(router)
        pd_intfs = l3_test_common.get_unassigned_pd_interfaces(update_router)

        # Get prefixes
        self._pd_get_prefixes(agent, ri, [], pd_intfs, mock_get_prefix)

        # Update the router with the new prefix
        ri.router = update_router
        ri.process()

        self._pd_verify_update_results(ri, pd_intfs, mock_pd_update_subnet)

        # Turn the router to be standby
        agent.pd.process_ha_state(router['id'], False)

        expected_calls = []
        for intf in pd_intfs:
            requestor_id = self._pd_get_requestor_id(intf, ri)
            expected_calls += (self._pd_expected_call_external_process(
                requestor_id, ri, False, ha=True))

        self._pd_assert_dibbler_calls(expected_calls,
            self.external_process.mock_calls[-len(expected_calls):])

    @mock.patch.object(pd.PrefixDelegation, 'update_subnet')
    @mock.patch.object(dibbler.PDDibbler, 'get_prefix', autospec=True)
    @mock.patch.object(dibbler.os, 'getpid', return_value=1234)
    @mock.patch.object(pd.PrefixDelegation, '_is_lla_active',
                       return_value=True)
    @mock.patch.object(dibbler.os, 'chmod')
    @mock.patch.object(dibbler.shutil, 'rmtree')
    @mock.patch.object(pd.PrefixDelegation, '_get_sync_data')
    def test_pd_lla_already_exists(self, mock1, mock2, mock3, mock4,
                                   mock_getpid, mock_get_prefix,
                                   mock_pd_update_subnet):
        '''Test HA in the active router
        The intent is to test the PD code with HA. To avoid unnecessary
        complexities, use the regular router.
        '''
        # Initial setup
        agent, router, ri = self._pd_setup_agent_router(enable_ha=True)

        agent.pd.intf_driver = mock.MagicMock()
        agent.pd.intf_driver.add_ipv6_addr.side_effect = (
                ip_lib.IpAddressAlreadyExists())

        # Create one pd-enabled subnet and add router interface
        l3_test_common.router_append_pd_enabled_subnet(router)
        self._pd_add_gw_interface(agent, ri)
        ri.process()

        # No client should be started since it's standby router
        agent.pd.process_prefix_update()
        self.assertFalse(self.external_process.called)
        self.assertFalse(mock_get_prefix.called)

        update_router = copy.deepcopy(router)
        pd_intfs = l3_test_common.get_unassigned_pd_interfaces(update_router)

        # Turn the router to be active
        agent.pd.process_ha_state(router['id'], True)

        # Get prefixes
        self._pd_get_prefixes(agent, ri, [], pd_intfs, mock_get_prefix)

        # Update the router with the new prefix
        ri.router = update_router
        ri.process()

        self._pd_verify_update_results(ri, pd_intfs, mock_pd_update_subnet)

    @mock.patch.object(dibbler.os, 'chmod')
    def test_pd_generate_dibbler_conf(self, mock_chmod):
        pddib = dibbler.PDDibbler("router_id", "subnet-id", "ifname")

        pddib._generate_dibbler_conf("ex_gw_ifname",
                                     "fe80::f816:3eff:fef5:a04e", None)
        expected = 'bind-to-address fe80::f816:3eff:fef5:a04e\n'\
                   '# ask for address\n   \n    pd 1\n   \n}'
        self.assertIn(expected, self.utils_replace_file.call_args[0][1])

        pddib._generate_dibbler_conf("ex_gw_ifname",
                                     "fe80::f816:3eff:fef5:a04e",
                                     "2001:db8:2c50:2026::/64")
        expected = 'bind-to-address fe80::f816:3eff:fef5:a04e\n'\
                   '# ask for address\n   \n    pd 1 '\
                   '{\n        prefix 2001:db8:2c50:2026::/64\n    }\n   \n}'
        self.assertIn(expected, self.utils_replace_file.call_args[0][1])

    def _verify_address_scopes_iptables_rule(self, mock_iptables_manager):
        filter_calls = [mock.call.add_chain('scope'),
                        mock.call.add_rule('FORWARD', '-j $scope')]
        v6_mangle_calls = [mock.call.add_chain('scope'),
                           mock.call.add_rule('PREROUTING', '-j $scope'),
                           mock.call.add_rule(
                               'PREROUTING',
                               '-m connmark ! --mark 0x0/0xffff0000 '
                               '-j CONNMARK --restore-mark '
                               '--nfmask 0xffff0000 --ctmask 0xffff0000')]
        v4_mangle_calls = (v6_mangle_calls +
                           [mock.call.add_chain('floatingip'),
                            mock.call.add_chain('float-snat'),
                            mock.call.add_rule('PREROUTING', '-j $floatingip'),
                            mock.call.add_rule(
                                'PREROUTING',
                                '-d 169.254.169.254/32 -i %(interface_name)s '
                                '-p tcp -m tcp --dport 80 '
                                '-j MARK --set-xmark %(value)s/%(mask)s' %
                                {'interface_name':
                                 namespaces.INTERNAL_DEV_PREFIX + '+',
                                 'value': self.conf.metadata_access_mark,
                                 'mask': lib_constants.ROUTER_MARK_MASK}),
                            mock.call.add_rule(
                                'float-snat',
                                '-m connmark --mark 0x0/0xffff0000 '
                                '-j CONNMARK --save-mark '
                                '--nfmask 0xffff0000 --ctmask 0xffff0000')])
        mock_iptables_manager.ipv4['filter'].assert_has_calls(filter_calls)
        mock_iptables_manager.ipv6['filter'].assert_has_calls(filter_calls)
        mock_iptables_manager.ipv4['mangle'].assert_has_calls(v4_mangle_calls,
                                                              any_order=True)
        mock_iptables_manager.ipv6['mangle'].assert_has_calls(v6_mangle_calls,
                                                              any_order=True)

    def test_initialize_address_scope_iptables_rules(self):
        id = _uuid()
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        with mock.patch('neutron.agent.linux.iptables_manager.'
                        'IptablesManager'):
            ri = l3router.RouterInfo(agent, id, {}, **self.ri_kwargs)
            self._verify_address_scopes_iptables_rule(ri.iptables_manager)

    def test_initialize_address_scope_iptables_rules_dvr(self):
        router = l3_test_common.prepare_router_data()
        with mock.patch('neutron.agent.linux.iptables_manager.'
                        'IptablesManager'):
            self._set_ri_kwargs(mock.Mock(), router['id'], router)
            ri = dvr_router.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
            self._verify_address_scopes_iptables_rule(ri.iptables_manager)
            interface_name, ex_gw_port = l3_test_common.prepare_ext_gw_test(
                self, ri)
            router['gw_port_host'] = ri.host
            ri._external_gateway_added = mock.Mock()
            ri._create_dvr_gateway(ex_gw_port, interface_name)
            self._verify_address_scopes_iptables_rule(
                ri.snat_iptables_manager)

    def _verify_metadata_iptables_rule(self, mock_iptables_manager):
        v4_mangle_calls = ([mock.call.add_rule(
                                'PREROUTING',
                                '-d 169.254.169.254/32 -i %(interface_name)s '
                                '-p tcp -m tcp --dport 80 '
                                '-j MARK --set-xmark %(value)s/%(mask)s' %
                                {'interface_name':
                                 namespaces.INTERNAL_DEV_PREFIX + '+',
                                 'value': self.conf.metadata_access_mark,
                                 'mask': lib_constants.ROUTER_MARK_MASK})])
        mock_iptables_manager.ipv4['mangle'].assert_has_calls(v4_mangle_calls,
                                                              any_order=True)

    def test_initialize_metadata_iptables_rules(self):
        id = _uuid()
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        with mock.patch('neutron.agent.linux.iptables_manager.'
                        'IptablesManager'):
            ri = l3router.RouterInfo(agent, id, {}, **self.ri_kwargs)
            self._verify_metadata_iptables_rule(ri.iptables_manager)

    @mock.patch.object(l3router.RouterInfo, 'delete')
    @mock.patch.object(ha_router.HaRouter, 'destroy_state_change_monitor')
    def test_delete_ha_router_initialize_fails(self, mock_dscm, mock_delete):
        router = l3_test_common.prepare_router_data(enable_ha=True)
        router[lib_constants.HA_INTERFACE_KEY] = None
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        # an early failure of an HA router initiailization shouldn't try
        # and cleanup a state change monitor process that was never spawned.
        # Cannot use self.assertRaises(Exception, ...) as that causes an H202
        # pep8 failure.
        try:
            agent._router_added(router['id'], router)
            raise Exception("agent._router_added() should have raised an "
                            "exception")
        except Exception:
            pass
        self.assertTrue(mock_delete.called)
        self.assertFalse(mock_dscm.called)

    @mock.patch.object(lla.LinkLocalAllocator, '_write')
    @mock.patch.object(l3router.RouterInfo, '_get_gw_ips_cidr')
    def test_process_floating_ip_addresses_not_care_port_forwarding(
            self, mock_get_gw_cidr, mock_lla_write):
        pf_used_fip = [{'cidr': '15.1.2.4/32'}, {'cidr': '15.1.2.5/32'}]
        gw_cidr = {'cidr': '15.1.2.79/24'}
        need_to_remove_fip = [{'cidr': '15.1.2.99/32'}]
        fake_floatingips = {'floatingips': [
            {'id': _uuid(),
             'floating_ip_address': '15.1.2.3',
             'fixed_ip_address': '192.168.0.1',
             'status': 'DOWN',
             'floating_network_id': _uuid(),
             'port_id': _uuid(),
             'host': HOSTNAME}]}

        router = l3_test_common.prepare_router_data(enable_snat=True)
        router[lib_constants.FLOATINGIP_KEY] = fake_floatingips['floatingips']
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = l3router.RouterInfo(agent, router['id'],
                                 router, **self.ri_kwargs)
        ri.centralized_port_forwarding_fip_set = set(
            [i['cidr'] for i in pf_used_fip])
        ri.iptables_manager.ipv4['nat'] = mock.MagicMock()
        ri.get_external_device_name = mock.Mock(return_value='exgw')
        floating_ips = ri.get_floating_ips()
        fip_id = floating_ips[0]['id']
        device = self.mock_ip_dev
        device.addr.list.return_value = (
                pf_used_fip + need_to_remove_fip + [gw_cidr])
        ri.iptables_manager.ipv4['nat'] = mock.MagicMock()
        mock_get_gw_cidr.return_value = set([gw_cidr['cidr']])
        ri.add_floating_ip = mock.Mock(
            return_value=lib_constants.FLOATINGIP_STATUS_ACTIVE)
        ri.remove_floating_ip = mock.Mock()
        fip_statuses = ri.process_floating_ip_addresses(
            mock.sentinel.interface_name)
        self.assertEqual({fip_id: lib_constants.FLOATINGIP_STATUS_ACTIVE},
                         fip_statuses)
        ri.add_floating_ip.assert_called_once_with(
            floating_ips[0], mock.sentinel.interface_name, device)
        ri.remove_floating_ip.assert_called_once_with(
            device, need_to_remove_fip[0]['cidr'])

    @mock.patch.object(functools, 'partial')
    @mock.patch.object(common_utils, 'load_interface_driver')
    def test_interface_driver_init(self, load_driver_mock, funct_partial_mock):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        load_driver_mock.assert_called_once_with(
                self.conf, get_networks_callback=mock.ANY)
        funct_partial_mock.assert_called_once_with(
            self.plugin_api.get_networks, agent.context)

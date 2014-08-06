# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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
from oslo.config import cfg
from webob import exc

import neutron
from neutron.api.v2 import attributes
from neutron import context as n_context
from neutron.db import agents_db
from neutron.db import common_db_mixin
from neutron.extensions import providernet as pnet
from neutron import manager
from neutron.openstack.common import timeutils
from neutron.plugins.cisco.common import cisco_constants as c_constants
from neutron.plugins.cisco.db.l3 import device_handling_db
from neutron.plugins.cisco.db.l3 import l3_router_appliance_db
from neutron.plugins.cisco.l3.rpc import devices_cfgagent_rpc_cb
from neutron.plugins.cisco.l3.rpc import l3_router_cfgagent_rpc_cb
from neutron.plugins.cisco.l3 import service_vm_lib
from neutron.plugins.common import constants as service_constants
from neutron.tests.unit.cisco.l3 import device_handling_test_support
from neutron.tests.unit import test_db_plugin
from neutron.tests.unit import test_extension_extraroute as test_ext_extraroute
from neutron.tests.unit import test_l3_plugin
from neutron.tests.unit import testlib_plugin


CORE_PLUGIN_KLASS = ('neutron.tests.unit.cisco.l3.'
                     'test_l3_router_appliance_plugin.TestNoL3NatPlugin')
L3_PLUGIN_KLASS = (
    "neutron.tests.unit.cisco.l3.test_l3_router_appliance_plugin."
    "TestApplianceL3RouterServicePlugin")
extensions_path = neutron.plugins.__path__[0] + '/cisco/extensions'


class L3RouterApplianceTestExtensionManager(
        test_ext_extraroute.ExtraRouteTestExtensionManager):

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []

    def get_extended_resources(self, version):
        return pnet.get_extended_resources(version)


class TestNoL3NatPlugin(test_l3_plugin.TestNoL3NatPlugin,
                        agents_db.AgentDbMixin):

    # There is no need to expose agent REST API
    supported_extension_aliases = ["external-net", "provider"]
    NET_TYPE = 'vlan'

    def __init__(self):
        self.tags = {}
        self.tag = 1
        super(TestNoL3NatPlugin, self).__init__()

    def _make_network_dict(self, network, fields=None,
                           process_extensions=True):
        res = {'id': network['id'],
               'name': network['name'],
               'tenant_id': network['tenant_id'],
               'admin_state_up': network['admin_state_up'],
               'status': network['status'],
               'shared': network['shared'],
               'subnets': [subnet['id']
                           for subnet in network['subnets']]}
        try:
            tag = self.tags[network['id']]
        except KeyError:
            self.tag += 1
            tag = self.tag
            self.tags[network['id']] = tag
        res.update({pnet.PHYSICAL_NETWORK: 'phy',
                    pnet.NETWORK_TYPE: self.NET_TYPE,
                    pnet.SEGMENTATION_ID: tag})
        # Call auxiliary extend functions, if any
        if process_extensions:
            self._apply_dict_extend_functions(
                attributes.NETWORKS, res, network)
        return self._fields(res, fields)

    def get_network_profiles(self, context, filters=None, fields=None):
        return [{'id': "1234"}]

    def get_policy_profiles(self, context, filters=None, fields=None):
        return [{'id': "4321"}]


# A set routes capable L3 routing service plugin class supporting appliances
class TestApplianceL3RouterServicePlugin(
    agents_db.AgentDbMixin, common_db_mixin.CommonDbMixin,
    device_handling_db.DeviceHandlingMixin,
    l3_router_appliance_db.L3RouterApplianceDBMixin):

    supported_extension_aliases = ["router", "extraroute"]

    def __init__(self):
        self._setup_backlog_handling()
        self._svc_vm_mgr = service_vm_lib.ServiceVMManager()
        super(TestApplianceL3RouterServicePlugin, self).__init__()

    def get_plugin_type(self):
        return service_constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        return "L3 Routing Service Plugin for testing"


class L3RouterApplianceTestCaseBase(
    test_db_plugin.NeutronDbPluginV2TestCase,
    testlib_plugin.NotificationSetupHelper,
        device_handling_test_support.DeviceHandlingTestSupportMixin):

    def setUp(self, core_plugin=None, l3_plugin=None, ext_mgr=None):
        # Save the global RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for resource, attrs in attributes.RESOURCE_ATTRIBUTE_MAP.iteritems():
            self.saved_attr_map[resource] = attrs.copy()
        if not core_plugin:
            core_plugin = CORE_PLUGIN_KLASS
        if l3_plugin is None:
            l3_plugin = L3_PLUGIN_KLASS
        service_plugins = {'l3_plugin_name': l3_plugin}
        cfg.CONF.set_override('api_extensions_path', extensions_path)

        # for these tests we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        cfg.CONF.set_default('max_routes', 3)
        if ext_mgr is None:
            ext_mgr = L3RouterApplianceTestExtensionManager()

        super(L3RouterApplianceTestCaseBase, self).setUp(
            plugin=core_plugin, service_plugins=service_plugins,
            ext_mgr=ext_mgr)

        self.core_plugin = manager.NeutronManager.get_plugin()
        self.plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)

        self.setup_notification_driver()

        cfg.CONF.set_override('allow_sorting', True)
        test_opts = [
            cfg.StrOpt('auth_protocol', default='http'),
            cfg.StrOpt('auth_host', default='localhost'),
            cfg.IntOpt('auth_port', default=35357),
            cfg.StrOpt('admin_user', default='neutron'),
            cfg.StrOpt('admin_password', default='secrete')]
        cfg.CONF.register_opts(test_opts, 'keystone_authtoken')

        self._mock_l3_admin_tenant()
        self._create_mgmt_nw_for_tests(self.fmt)
        self._mock_svc_vm_create_delete(self.plugin)
        self._mock_io_file_ops()

    def restore_attribute_map(self):
        # Restore the original RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map

    def tearDown(self):
        self._remove_mgmt_nw_for_tests()
        (neutron.tests.unit.cisco.l3.test_l3_router_appliance_plugin.
            TestApplianceL3RouterServicePlugin._mgmt_nw_uuid) = None
        (neutron.tests.unit.cisco.l3.test_l3_router_appliance_plugin.
            TestApplianceL3RouterServicePlugin._refresh_router_backlog) = True
        (neutron.tests.unit.cisco.l3.test_l3_router_appliance_plugin.
            TestApplianceL3RouterServicePlugin._nova_running) = False
        plugin = manager.NeutronManager.get_service_plugins()[
            service_constants.L3_ROUTER_NAT]
        plugin._heartbeat.stop()
        self.restore_attribute_map()
        super(L3RouterApplianceTestCaseBase, self).tearDown()


class L3RouterApplianceVMTestCase(
    L3RouterApplianceTestCaseBase, test_l3_plugin.L3NatTestCaseBase,
        test_ext_extraroute.ExtraRouteDBTestCaseBase):

    def setUp(self, core_plugin=None, l3_plugin=None, dm_plugin=None,
              ext_mgr=None):
        super(L3RouterApplianceVMTestCase, self).setUp(
            core_plugin=core_plugin, l3_plugin=l3_plugin, ext_mgr=ext_mgr)

    def test_floatingip_with_assoc_fails(self):
        self._test_floatingip_with_assoc_fails(
            'neutron.db.l3_db.L3_NAT_dbonly_mixin._check_and_get_fip_assoc')


class L3RouterApplianceVMTestCaseXML(L3RouterApplianceVMTestCase):
    fmt = 'xml'


class CfgAgentRouterApplianceVMTestCase(L3RouterApplianceTestCaseBase,
                                        test_l3_plugin.L3AgentDbTestCaseBase):

    def setUp(self, core_plugin=None, l3_plugin=None, ext_mgr=None):
        super(CfgAgentRouterApplianceVMTestCase, self).setUp(
            core_plugin=core_plugin, l3_plugin=l3_plugin, ext_mgr=ext_mgr)
        # Rewire function name so we can use existing l3 agent tests
        # to test the cfg agent rpc.
        self.plugin.get_sync_data = self.plugin.get_sync_data_ext

    def _test_notify_op_agent(self, target_func, *args):
        l3_rpc_agent_api_str = (
            'neutron.plugins.cisco.l3.rpc.l3_router_rpc_joint_agent_api'
            '.L3RouterJointAgentNotifyAPI')
        plugin = manager.NeutronManager.get_service_plugins()[
            service_constants.L3_ROUTER_NAT]
        oldNotify = plugin.l3_cfg_rpc_notifier
        try:
            with mock.patch(l3_rpc_agent_api_str) as notifyApi:
                plugin.l3_cfg_rpc_notifier = notifyApi
                kargs = [item for item in args]
                kargs.append(notifyApi)
                target_func(*kargs)
        except Exception:
            plugin.l3_cfg_rpc_notifier = oldNotify
            raise
        else:
            plugin.l3_cfg_rpc_notifier = oldNotify


DB_PLUGIN_KLASS = ('neutron.tests.unit.cisco.l3.ovs_neutron_plugin.'
                   'OVSNeutronPluginV2')

HOST = 'my_cfgagent_host'
FIRST_CFG_AGENT = {
    'binary': 'neutron-cisco-cfg-agent',
    'host': HOST,
    'topic': c_constants.CFG_AGENT,
    'configurations': {},
    'agent_type': c_constants.AGENT_TYPE_CFG,
    'start_flag': True
}


class RouterSchedulingTestCase(L3RouterApplianceTestCaseBase,
                               test_l3_plugin.L3NatTestCaseMixin):

    def setUp(self):
        super(RouterSchedulingTestCase, self).setUp()
        self.adminContext = n_context.get_admin_context()

    def _register_cfg_agent(self):
        callback = agents_db.AgentExtRpcCallback()
        callback.report_state(self.adminContext,
                              agent_state={'agent_state': FIRST_CFG_AGENT},
                              time=timeutils.strtime())
        agent_db = self.core_plugin.get_agents_db(self.adminContext,
                                                  filters={'host': [HOST]})
        self.agent_id1 = agent_db[0].id

    def _update_router_name(self, router_id, new_name='new_name'):
        return self._update('routers', router_id,
                            {'router': {'name': new_name}},
                            expected_code=exc.HTTPOk.code)

    def test_router_scheduled_to_device_with_no_cfg_agent(self):
        with self.router() as router:
            r_id = router['router']['id']
            self._update_router_name(r_id)
            routers = self.plugin.get_sync_data_ext(self.adminContext,
                                                    [r_id])
            self.assertEqual(1, len(routers))
            hosting_device = routers[0]['hosting_device']
            self.assertIsNotNone(hosting_device)
            self.assertIsNone(hosting_device['cfg_agent_id'])

    def test_router_not_scheduled_to_device_without_nova_services(self):
        self._nclient_services_mock.list = self._novaclient_services_list(
            False)
        with self.router() as router:
            r_id = router['router']['id']
            self._update_router_name(r_id)
            routers = self.plugin.get_sync_data_ext(self.adminContext,
                                                    [r_id])
            self.assertEqual(1, len(routers))
            hosting_device = routers[0]['hosting_device']
            self.assertIsNone(hosting_device)

    def test_router_scheduled_to_device_and_cfg_agent(self):
        self._register_cfg_agent()
        cfg_rpc = l3_router_cfgagent_rpc_cb.L3RouterCfgRpcCallbackMixin()
        cfg_rpc._core_plugin = self.core_plugin
        cfg_rpc._l3plugin = self.plugin
        with self.router() as router:
            r_id = router['router']['id']
            self._update_router_name(r_id)
            routers = cfg_rpc.cfg_sync_routers(
                self.adminContext, host=HOST)
            self.assertEqual(1, len(routers))
            hosting_device = routers[0]['hosting_device']
            self.assertIsNotNone(hosting_device)
            self.assertIsNotNone(hosting_device['cfg_agent_id'])

    def test_dead_device_is_removed(self):
        cfg_dh_rpc = devices_cfgagent_rpc_cb.DeviceCfgRpcCallbackMixin()
        cfg_dh_rpc._l3plugin = self.plugin
        with mock.patch(
                'neutron.plugins.cisco.l3.rpc.l3_router_rpc_joint_agent_api.'
                'L3RouterJointAgentNotifyAPI.hosting_devices_removed') as (
                mock_notify):
            with self.router() as router:
                r_id = router['router']['id']
                routers_1 = self.plugin.get_sync_data_ext(self.adminContext,
                                                          [r_id])
                self.assertEqual(1, len(routers_1))
                hosting_device_1 = routers_1[0]['hosting_device']
                self.assertIsNotNone(hosting_device_1)
                cfg_dh_rpc.report_non_responding_hosting_devices(
                    self.adminContext,
                    host = None,
                    hosting_device_ids=[hosting_device_1['id']])
            self.assertEqual(1, mock_notify.call_count)
            mock_notify.assert_called_with(
                mock.ANY,
                {hosting_device_1['id']: {'routers': [r_id]}},
                False,
                mock.ANY)

    def test_cfg_agent_registration_triggers_autoscheduling(self):
        with self.router() as router:
            r_id = router['router']['id']
            routers_1 = self.plugin.get_sync_data_ext(self.adminContext,
                                                      [r_id])
            self.assertEqual(1, len(routers_1))
            hosting_device_1 = routers_1[0]['hosting_device']
            self.assertIsNotNone(hosting_device_1)
            self.assertIsNone(hosting_device_1['cfg_agent_id'])
            cfg_dh_rpc = devices_cfgagent_rpc_cb.DeviceCfgRpcCallbackMixin()
            cfg_dh_rpc._l3plugin = self.plugin
            self._register_cfg_agent()
            res = cfg_dh_rpc.register_for_duty(self.adminContext, host=HOST)
            self.assertTrue(res)
            routers_2 = self.plugin.get_sync_data_ext(self.adminContext,
                                                      [r_id])
            self.assertEqual(1, len(routers_2))
            hosting_device_2 = routers_2[0]['hosting_device']
            self.assertIsNotNone(hosting_device_2)
            self.assertIsNotNone(hosting_device_2['cfg_agent_id'])

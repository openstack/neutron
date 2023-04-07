# Copyright 2013 VMware, Inc.
# All rights reserved.
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

from unittest import mock

import netaddr
from neutron_lib.api.definitions import external_net as enet_apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import l3_ext_gw_mode
from neutron_lib import constants
from neutron_lib import context as nctx
from neutron_lib.db import api as db_api
from neutron_lib.plugins import directory
from neutron_lib.utils import net as net_utils
from oslo_db import exception as db_exc
from oslo_serialization import jsonutils
from oslo_utils import uuidutils
import testscenarios
from webob import exc

from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.db.models import l3 as l3_models
from neutron.extensions import l3
from neutron.objects import network as net_obj
from neutron.objects import ports as port_obj
from neutron.objects import router as l3_obj
from neutron.objects import subnet as subnet_obj
from neutron.tests import base
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit import testlib_api

_uuid = uuidutils.generate_uuid
FAKE_GW_PORT_ID = _uuid()
FAKE_GW_PORT_MAC = 'aa:bb:cc:dd:ee:ff'
FAKE_FIP_EXT_PORT_ID = _uuid()
FAKE_FIP_EXT_PORT_MAC = '11:22:33:44:55:66'
FAKE_FIP_INT_PORT_ID = _uuid()
FAKE_FIP_INT_PORT_MAC = 'aa:aa:aa:aa:aa:aa'
FAKE_ROUTER_PORT_ID = _uuid()
FAKE_ROUTER_PORT_MAC = 'bb:bb:bb:bb:bb:bb'


class TestExtensionManager(object):

    def get_resources(self):
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


# A simple class for making a concrete class out of the mixin
# for the case of a plugin that integrates l3 routing.
class TestDbIntPlugin(test_l3.TestL3NatIntPlugin,
                      l3_gwmode_db.L3_NAT_db_mixin):

    supported_extension_aliases = [enet_apidef.ALIAS, l3_apidef.ALIAS,
                                   l3_ext_gw_mode.ALIAS]


# A simple class for making a concrete class out of the mixin
# for the case of a l3 router service plugin
class TestDbSepPlugin(test_l3.TestL3NatServicePlugin,
                      l3_gwmode_db.L3_NAT_db_mixin):

    supported_extension_aliases = [l3_apidef.ALIAS, l3_ext_gw_mode.ALIAS]


class TestGetEnableSnat(testscenarios.WithScenarios, base.BaseTestCase):
    scenarios = [
        ('enabled', {'enable_snat_by_default': True}),
        ('disabled', {'enable_snat_by_default': False})]

    def setUp(self):
        super(TestGetEnableSnat, self).setUp()
        self.config(enable_snat_by_default=self.enable_snat_by_default)

    def _test_get_enable_snat(self, expected, info):
        observed = l3_gwmode_db.L3_NAT_dbonly_mixin._get_enable_snat(info)
        self.assertEqual(expected, observed)

    def test_get_enable_snat_without_gw_info(self):
        self._test_get_enable_snat(self.enable_snat_by_default, {})

    def test_get_enable_snat_without_enable_snat(self):
        info = {'network_id': _uuid()}
        self._test_get_enable_snat(self.enable_snat_by_default, info)

    def test_get_enable_snat_with_snat_enabled(self):
        self._test_get_enable_snat(True, {'enable_snat': True})

    def test_get_enable_snat_with_snat_disabled(self):
        self._test_get_enable_snat(False, {'enable_snat': False})


class TestL3GwModeMixin(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestL3GwModeMixin, self).setUp()
        plugin = __name__ + '.' + TestDbIntPlugin.__name__
        self.setup_coreplugin(plugin)
        self.target_object = TestDbIntPlugin()
        # Patch the context
        ctx_patcher = mock.patch('neutron_lib.context', autospec=True)
        mock_context = ctx_patcher.start()
        self.context = mock_context.get_admin_context()
        # This ensure also calls to elevated work in unit tests
        self.context.elevated.return_value = self.context
        self.context.session = db_api.get_writer_session()
        # Create sample data for tests
        self.ext_net_id = _uuid()
        self.int_net_id = _uuid()
        self.int_sub_id = _uuid()
        self.tenant_id = 'the_tenant'
        self.network = net_obj.Network(
            self.context,
            id=self.ext_net_id,
            project_id=self.tenant_id,
            admin_state_up=True,
            status=constants.NET_STATUS_ACTIVE)
        self.net_ext = net_obj.ExternalNetwork(
            self.context, network_id=self.ext_net_id)
        self.network.create()
        self.net_ext.create()
        self.router = l3_models.Router(
            id=_uuid(),
            name=None,
            tenant_id=self.tenant_id,
            admin_state_up=True,
            status=constants.NET_STATUS_ACTIVE,
            enable_snat=True,
            gw_port_id=None)
        self.context.session.add(self.router)
        self.context.session.flush()
        self.router_gw_port = port_obj.Port(
            self.context,
            id=FAKE_GW_PORT_ID,
            project_id=self.tenant_id,
            device_id=self.router.id,
            device_owner=l3_db.DEVICE_OWNER_ROUTER_GW,
            admin_state_up=True,
            status=constants.PORT_STATUS_ACTIVE,
            mac_address=netaddr.EUI(FAKE_GW_PORT_MAC),
            network_id=self.ext_net_id)
        self.router_gw_port.create()
        self.router.gw_port_id = self.router_gw_port.id
        self.context.session.add(self.router)
        self.context.session.flush()
        self.fip_ext_port = port_obj.Port(
            self.context,
            id=FAKE_FIP_EXT_PORT_ID,
            project_id=self.tenant_id,
            admin_state_up=True,
            device_id=self.router.id,
            device_owner=l3_db.DEVICE_OWNER_FLOATINGIP,
            status=constants.PORT_STATUS_ACTIVE,
            mac_address=netaddr.EUI(FAKE_FIP_EXT_PORT_MAC),
            network_id=self.ext_net_id)
        self.fip_ext_port.create()
        self.context.session.flush()
        self.int_net = net_obj.Network(
            self.context,
            id=self.int_net_id,
            project_id=self.tenant_id,
            admin_state_up=True,
            status=constants.NET_STATUS_ACTIVE)
        self.int_sub = subnet_obj.Subnet(self.context,
            id=self.int_sub_id,
            project_id=self.tenant_id,
            ip_version=constants.IP_VERSION_4,
            cidr=net_utils.AuthenticIPNetwork('3.3.3.0/24'),
            gateway_ip=netaddr.IPAddress('3.3.3.1'),
            network_id=self.int_net_id)
        self.router_port = port_obj.Port(
            self.context,
            id=FAKE_ROUTER_PORT_ID,
            project_id=self.tenant_id,
            admin_state_up=True,
            device_id=self.router.id,
            device_owner=l3_db.DEVICE_OWNER_ROUTER_INTF,
            status=constants.PORT_STATUS_ACTIVE,
            mac_address=netaddr.EUI(FAKE_ROUTER_PORT_MAC),
            network_id=self.int_net_id)
        self.router_port_ip_info = port_obj.IPAllocation(self.context,
            port_id=self.router_port.id,
            network_id=self.int_net.id,
            subnet_id=self.int_sub_id,
            ip_address='3.3.3.1')
        self.int_net.create()
        self.int_sub.create()
        self.router_port.create()
        self.router_port_ip_info.create()
        self.context.session.flush()
        self.fip_int_port = port_obj.Port(
            self.context,
            id=FAKE_FIP_INT_PORT_ID,
            project_id=self.tenant_id,
            admin_state_up=True,
            device_id='something',
            device_owner=constants.DEVICE_OWNER_COMPUTE_PREFIX + 'nova',
            status=constants.PORT_STATUS_ACTIVE,
            mac_address=netaddr.EUI(FAKE_FIP_INT_PORT_MAC),
            network_id=self.int_net_id)
        self.fip_int_ip_info = port_obj.IPAllocation(self.context,
            port_id=self.fip_int_port.id,
            network_id=self.int_net.id,
            subnet_id=self.int_sub_id,
            ip_address='3.3.3.3')
        self.fip = l3_obj.FloatingIP(
            self.context,
            id=_uuid(),
            floating_ip_address=netaddr.IPAddress('1.1.1.2'),
            floating_network_id=self.ext_net_id,
            floating_port_id=FAKE_FIP_EXT_PORT_ID,
            fixed_port_id=None,
            fixed_ip_address=None,
            router_id=None)
        self.fip_int_port.create()
        self.fip_int_ip_info.create()
        self.fip.create()
        self.context.session.flush()
        self.context.session.expire_all()
        self.fip_request = {'port_id': FAKE_FIP_INT_PORT_ID,
                            'tenant_id': self.tenant_id}

    def _get_gwports_dict(self, gw_ports):
        return dict((gw_port['id'], gw_port)
                    for gw_port in gw_ports)

    def _reset_ext_gw(self):
        # Reset external gateway
        self.router.gw_port_id = None
        self.context.session.add(self.router)
        self.context.session.flush()

    def _test_update_router_gw(self, current_enable_snat, gw_info=None,
                               expected_enable_snat=True):
        if not current_enable_snat:
            previous_gw_info = {'network_id': self.ext_net_id,
                                'enable_snat': current_enable_snat}
            request_body = {
                l3_apidef.EXTERNAL_GW_INFO: previous_gw_info}
            self.target_object._update_router_gw_info(
                self.context, self.router.id, previous_gw_info, request_body)

        request_body = {
            l3_apidef.EXTERNAL_GW_INFO: gw_info}
        self.target_object._update_router_gw_info(
            self.context, self.router.id, gw_info, request_body)
        router = self.target_object._get_router(
            self.context, self.router.id)
        try:
            self.assertEqual(FAKE_GW_PORT_ID,
                             router.gw_port.id)
            self.assertEqual(netaddr.EUI(FAKE_GW_PORT_MAC),
                             router.gw_port.mac_address)
        except AttributeError:
            self.assertIsNone(router.gw_port)
        self.assertEqual(expected_enable_snat, router.enable_snat)

    def test_update_router_gw_with_gw_info_none(self):
        self._test_update_router_gw(current_enable_snat=True)

    def test_update_router_gw_without_info_and_snat_disabled_previously(self):
        self._test_update_router_gw(current_enable_snat=False)

    def test_update_router_gw_with_network_only(self):
        info = {'network_id': self.ext_net_id}
        self._test_update_router_gw(current_enable_snat=True, gw_info=info)

    def test_update_router_gw_with_network_and_snat_disabled_previously(self):
        info = {'network_id': self.ext_net_id}
        self._test_update_router_gw(current_enable_snat=False, gw_info=info)

    def test_update_router_gw_with_snat_disabled(self):
        info = {'network_id': self.ext_net_id,
                'enable_snat': False}
        self._test_update_router_gw(
            current_enable_snat=True, gw_info=info, expected_enable_snat=False)

    def test_update_router_gw_with_snat_enabled(self):
        info = {'network_id': self.ext_net_id,
                'enable_snat': True}
        self._test_update_router_gw(current_enable_snat=False, gw_info=info)

    def test_make_router_dict_no_ext_gw(self):
        self._reset_ext_gw()
        router_dict = self.target_object._make_router_dict(self.router)
        self.assertIsNone(router_dict[l3_apidef.EXTERNAL_GW_INFO])

    def test_make_router_dict_with_ext_gw(self):
        router_dict = self.target_object._make_router_dict(self.router)
        self.assertEqual({'network_id': self.ext_net_id,
                          'enable_snat': True,
                          'external_fixed_ips': []},
                         router_dict[l3_apidef.EXTERNAL_GW_INFO])

    def test_make_router_dict_with_ext_gw_snat_disabled(self):
        self.router.enable_snat = False
        router_dict = self.target_object._make_router_dict(self.router)
        self.assertEqual({'network_id': self.ext_net_id,
                          'enable_snat': False,
                          'external_fixed_ips': []},
                         router_dict[l3_apidef.EXTERNAL_GW_INFO])

    def test_build_routers_list_no_ext_gw(self):
        self._reset_ext_gw()
        router_dict = self.target_object._make_router_dict(self.router)
        routers = self.target_object._build_routers_list(self.context,
                                                         [router_dict],
                                                         [])
        self.assertEqual(1, len(routers))
        router = routers[0]
        self.assertIsNone(router.get('gw_port'))
        self.assertIsNone(router.get('enable_snat'))

    def test_build_routers_list_with_ext_gw(self):
        router_dict = self.target_object._make_router_dict(self.router)
        routers = self.target_object._build_routers_list(
            self.context, [router_dict],
            self._get_gwports_dict([self.router.gw_port]))
        self.assertEqual(1, len(routers))
        router = routers[0]
        self.assertIsNotNone(router.get('gw_port'))
        self.assertEqual(FAKE_GW_PORT_ID, router['gw_port']['id'])
        self.assertTrue(router.get('enable_snat'))

    def test_build_routers_list_with_ext_gw_snat_disabled(self):
        self.router.enable_snat = False
        router_dict = self.target_object._make_router_dict(self.router)
        routers = self.target_object._build_routers_list(
            self.context, [router_dict],
            self._get_gwports_dict([self.router.gw_port]))
        self.assertEqual(1, len(routers))
        router = routers[0]
        self.assertIsNotNone(router.get('gw_port'))
        self.assertEqual(FAKE_GW_PORT_ID, router['gw_port']['id'])
        self.assertFalse(router.get('enable_snat'))

    def test_build_routers_list_with_gw_port_mismatch(self):
        router_dict = self.target_object._make_router_dict(self.router)
        routers = self.target_object._build_routers_list(
            self.context, [router_dict], {})
        self.assertEqual(1, len(routers))
        router = routers[0]
        self.assertIsNone(router.get('gw_port'))
        self.assertIsNone(router.get('enable_snat'))


class ExtGwModeIntTestCase(test_db_base_plugin_v2.NeutronDbPluginV2TestCase,
                           test_l3.L3NatTestCaseMixin):

    def setUp(self, plugin=None, svc_plugins=None, ext_mgr=None):
        plugin = plugin or (
            'neutron.tests.unit.extensions.test_l3_ext_gw_mode.'
            'TestDbIntPlugin')
        ext_mgr = ext_mgr or TestExtensionManager()
        super(ExtGwModeIntTestCase, self).setUp(plugin=plugin,
                                                ext_mgr=ext_mgr,
                                                service_plugins=svc_plugins)

    def _set_router_external_gateway(self, router_id, network_id,
                                     snat_enabled=None,
                                     expected_code=exc.HTTPOk.code,
                                     tenant_id=None, as_admin=False):
        ext_gw_info = {'network_id': network_id}
        # Need to set enable_snat also if snat_enabled == False
        if snat_enabled is not None:
            ext_gw_info['enable_snat'] = snat_enabled
        return self._update('routers', router_id,
                            {'router': {'external_gateway_info':
                                        ext_gw_info}},
                            expected_code=expected_code,
                            request_tenant_id=tenant_id,
                            as_admin=as_admin)

    def test_router_gateway_set_fail_after_port_create(self):
        with self.router() as r, self.subnet() as s:
            ext_net_id = s['subnet']['network_id']
            self._set_net_external(ext_net_id)
            plugin = directory.get_plugin()
            with mock.patch.object(plugin, '_get_port',
                                   side_effect=ValueError()):
                self._set_router_external_gateway(r['router']['id'],
                                                  ext_net_id,
                                                  expected_code=500)
            ports = [p for p in plugin.get_ports(nctx.get_admin_context())
                     if p['device_owner'] == l3_db.DEVICE_OWNER_ROUTER_GW]
            self.assertFalse(ports)

    def test_router_gateway_set_retry(self):
        with self.router() as r, self.subnet() as s:
            ext_net_id = s['subnet']['network_id']
            self._set_net_external(ext_net_id)
            with mock.patch.object(
                    l3_db.L3_NAT_dbonly_mixin, '_validate_gw_info',
                    side_effect=[db_exc.RetryRequest(None), ext_net_id]):
                self._set_router_external_gateway(r['router']['id'],
                                                  ext_net_id)
            res = self._show('routers', r['router']['id'])['router']
            self.assertEqual(ext_net_id,
                             res['external_gateway_info']['network_id'])

    def test_router_create_with_gwinfo_invalid_ext_ip(self):
        with self.subnet() as s:
            self._set_net_external(s['subnet']['network_id'])
            ext_info = {
                'network_id': s['subnet']['network_id'],
                'external_fixed_ips': [{'ip_address': '10.0.0.'}]
            }
            error_code = exc.HTTPBadRequest.code
            res = self._create_router(
                self.fmt, _uuid(), arg_list=('external_gateway_info',),
                external_gateway_info=ext_info,
                expected_code=error_code
            )
            msg = ("Invalid input for external_gateway_info. "
                   "Reason: '10.0.0.' is not a valid IP address.")
            body = jsonutils.loads(res.body)
            self.assertEqual(msg, body['NeutronError']['message'])

    def test_router_create_show_no_ext_gwinfo(self):
        name = 'router1'
        tenant_id = _uuid()
        expected_value = [('name', name), ('tenant_id', tenant_id),
                          ('admin_state_up', True), ('status', 'ACTIVE'),
                          ('external_gateway_info', None)]
        with self.router(name=name, admin_state_up=True,
                         tenant_id=tenant_id) as router:
            res = self._show('routers', router['router']['id'],
                             tenant_id=tenant_id)
            for k, v in expected_value:
                self.assertEqual(res['router'][k], v)

    def _test_router_create_show_ext_gwinfo(self, snat_input_value,
                                            snat_expected_value):
        name = 'router1'
        tenant_id = _uuid()
        with self.subnet() as s:
            ext_net_id = s['subnet']['network_id']
            self._set_net_external(ext_net_id)
            input_value = {'network_id': ext_net_id}
            if snat_input_value in (True, False):
                input_value['enable_snat'] = snat_input_value
            expected_value = [('name', name), ('tenant_id', tenant_id),
                              ('admin_state_up', True), ('status', 'ACTIVE'),
                              ('external_gateway_info',
                               {'network_id': ext_net_id,
                                'enable_snat': snat_expected_value,
                                'external_fixed_ips': [{
                                    'ip_address': mock.ANY,
                                    'subnet_id': s['subnet']['id']}]})]
            with self.router(name=name, admin_state_up=True,
                             tenant_id=tenant_id,
                             external_gateway_info=input_value,
                             as_admin=True) as router:
                res = self._show('routers', router['router']['id'],
                                 tenant_id=tenant_id)
                for k, v in expected_value:
                    self.assertEqual(v, res['router'][k])

    def test_router_create_show_ext_gwinfo_default(self):
        self._test_router_create_show_ext_gwinfo(None, True)

    def test_router_create_show_ext_gwinfo_with_snat_enabled(self):
        self._test_router_create_show_ext_gwinfo(True, True)

    def test_router_create_show_ext_gwinfo_with_snat_disabled(self):
        self._test_router_create_show_ext_gwinfo(False, False)

    def _test_router_update_ext_gwinfo(self, snat_input_value,
                                       snat_expected_value=False,
                                       expected_http_code=exc.HTTPOk.code):
        with self.router() as r:
            with self.subnet() as s:
                try:
                    ext_net_id = s['subnet']['network_id']
                    self._set_net_external(ext_net_id)
                    self._set_router_external_gateway(
                        r['router']['id'], ext_net_id,
                        snat_enabled=snat_input_value,
                        expected_code=expected_http_code,
                        as_admin=True)
                    if expected_http_code != exc.HTTPOk.code:
                        return
                    body = self._show('routers', r['router']['id'])
                    res_gw_info = body['router']['external_gateway_info']
                    self.assertEqual(ext_net_id, res_gw_info['network_id'])
                    self.assertEqual(snat_expected_value,
                                     res_gw_info['enable_snat'])
                finally:
                    self._remove_external_gateway_from_router(
                        r['router']['id'], ext_net_id)

    def test_router_update_ext_gwinfo_default(self):
        self._test_router_update_ext_gwinfo(None, True)

    def test_router_update_ext_gwinfo_with_snat_enabled(self):
        self._test_router_update_ext_gwinfo(True, True)

    def test_router_update_ext_gwinfo_with_snat_disabled(self):
        self._test_router_update_ext_gwinfo(False, False)

    def test_router_update_ext_gwinfo_with_invalid_snat_setting(self):
        self._test_router_update_ext_gwinfo(
            'xxx', None, expected_http_code=exc.HTTPBadRequest.code)


class ExtGwModeSepTestCase(ExtGwModeIntTestCase):

    def setUp(self, plugin=None):
        # Store l3 resource attribute map as it will be updated
        self._l3_attribute_map_bk = {}
        for item in l3_apidef.RESOURCE_ATTRIBUTE_MAP:
            self._l3_attribute_map_bk[item] = (
                l3_apidef.RESOURCE_ATTRIBUTE_MAP[item].copy())
        plugin = plugin or (
            'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin')
        # the L3 service plugin
        l3_plugin = ('neutron.tests.unit.extensions.test_l3_ext_gw_mode.'
                     'TestDbSepPlugin')
        svc_plugins = {'l3_plugin_name': l3_plugin}
        super(ExtGwModeSepTestCase, self).setUp(plugin=plugin,
                                                svc_plugins=svc_plugins)

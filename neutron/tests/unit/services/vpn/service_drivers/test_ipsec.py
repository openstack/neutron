# Copyright 2013, Nachi Ueno, NTT I3, Inc.
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
from oslo.config import cfg

from neutron import context as n_ctx
from neutron.db import l3_db
from neutron.db import servicetype_db as st_db
from neutron.db.vpn import vpn_validator
from neutron.extensions import vpnaas
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.services.vpn import plugin as vpn_plugin
from neutron.services.vpn.service_drivers import ipsec as ipsec_driver
from neutron.tests import base

_uuid = uuidutils.generate_uuid

FAKE_SERVICE_ID = _uuid()
FAKE_VPN_CONNECTION = {
    'vpnservice_id': FAKE_SERVICE_ID
}
FAKE_ROUTER_ID = _uuid()
FAKE_VPN_SERVICE = {
    'router_id': FAKE_ROUTER_ID
}
FAKE_HOST = 'fake_host'
FAKE_ROUTER = {l3_db.EXTERNAL_GW_INFO: FAKE_ROUTER_ID}
FAKE_SUBNET_ID = _uuid()
IPV4 = 4
IPV6 = 6

IPSEC_SERVICE_DRIVER = ('neutron.services.vpn.service_drivers.'
                        'ipsec.IPsecVPNDriver')


class TestValidatorSelection(base.BaseTestCase):

    def setUp(self):
        super(TestValidatorSelection, self).setUp()
        vpnaas_provider = (constants.VPN + ':vpnaas:' +
                           IPSEC_SERVICE_DRIVER + ':default')
        cfg.CONF.set_override('service_provider',
                              [vpnaas_provider],
                              'service_providers')
        mock.patch('neutron.common.rpc.create_connection').start()
        stm = st_db.ServiceTypeManager()
        mock.patch('neutron.db.servicetype_db.ServiceTypeManager.get_instance',
                   return_value=stm).start()
        self.vpn_plugin = vpn_plugin.VPNDriverPlugin()

    def test_reference_driver_used(self):
        self.assertIsInstance(self.vpn_plugin._get_validator(),
                              vpn_validator.VpnReferenceValidator)


class TestIPsecDriverValidation(base.BaseTestCase):

    def setUp(self):
        super(TestIPsecDriverValidation, self).setUp()
        self.l3_plugin = mock.Mock()
        mock.patch(
            'neutron.manager.NeutronManager.get_service_plugins',
            return_value={constants.L3_ROUTER_NAT: self.l3_plugin}).start()
        self.core_plugin = mock.Mock()
        mock.patch('neutron.manager.NeutronManager.get_plugin',
                   return_value=self.core_plugin).start()
        self.context = n_ctx.Context('some_user', 'some_tenant')
        self.validator = vpn_validator.VpnReferenceValidator()

    def test_non_public_router_for_vpn_service(self):
        """Failure test of service validate, when router missing ext. I/F."""
        self.l3_plugin.get_router.return_value = {}  # No external gateway
        vpnservice = {'router_id': 123, 'subnet_id': 456}
        self.assertRaises(vpnaas.RouterIsNotExternal,
                          self.validator.validate_vpnservice,
                          self.context, vpnservice)

    def test_subnet_not_connected_for_vpn_service(self):
        """Failure test of service validate, when subnet not on router."""
        self.l3_plugin.get_router.return_value = FAKE_ROUTER
        self.core_plugin.get_ports.return_value = None
        vpnservice = {'router_id': FAKE_ROUTER_ID, 'subnet_id': FAKE_SUBNET_ID}
        self.assertRaises(vpnaas.SubnetIsNotConnectedToRouter,
                          self.validator.validate_vpnservice,
                          self.context, vpnservice)

    def test_defaults_for_ipsec_site_connections_on_create(self):
        """Check that defaults are applied correctly.

        MTU has a default and will always be present on create.
        However, the DPD settings do not have a default, so
        database create method will assign default values for any
        missing. In addition, the DPD dict will be flattened
        for storage into the database, so we'll do it as part of
        assigning defaults.
        """
        ipsec_sitecon = {}
        self.validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon)
        expected = {
            'dpd_action': 'hold',
            'dpd_timeout': 120,
            'dpd_interval': 30
        }
        self.assertEqual(expected, ipsec_sitecon)

        ipsec_sitecon = {'dpd': {'interval': 50}}
        self.validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon)
        expected = {
            'dpd': {'interval': 50},
            'dpd_action': 'hold',
            'dpd_timeout': 120,
            'dpd_interval': 50
        }
        self.assertEqual(expected, ipsec_sitecon)

    def test_defaults_for_ipsec_site_connections_on_update(self):
        """Check that defaults are used for any values not specified."""
        ipsec_sitecon = {}
        prev_connection = {'dpd_action': 'clear',
                           'dpd_timeout': 500,
                           'dpd_interval': 250}
        self.validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon,
                                                              prev_connection)
        expected = {
            'dpd_action': 'clear',
            'dpd_timeout': 500,
            'dpd_interval': 250
        }
        self.assertEqual(expected, ipsec_sitecon)

        ipsec_sitecon = {'dpd': {'timeout': 200}}
        prev_connection = {'dpd_action': 'clear',
                           'dpd_timeout': 500,
                           'dpd_interval': 100}
        self.validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon,
                                                              prev_connection)
        expected = {
            'dpd': {'timeout': 200},
            'dpd_action': 'clear',
            'dpd_timeout': 200,
            'dpd_interval': 100
        }
        self.assertEqual(expected, ipsec_sitecon)

    def test_bad_dpd_settings_on_create(self):
        """Failure tests of DPD settings for IPSec conn during create."""
        ipsec_sitecon = {'mtu': 1500, 'dpd_action': 'hold',
                         'dpd_interval': 100, 'dpd_timeout': 100}
        self.assertRaises(vpnaas.IPsecSiteConnectionDpdIntervalValueError,
                          self.validator.validate_ipsec_site_connection,
                          self.context, ipsec_sitecon, IPV4)
        ipsec_sitecon = {'mtu': 1500, 'dpd_action': 'hold',
                         'dpd_interval': 100, 'dpd_timeout': 99}
        self.assertRaises(vpnaas.IPsecSiteConnectionDpdIntervalValueError,
                          self.validator.validate_ipsec_site_connection,
                          self.context, ipsec_sitecon, IPV4)

    def test_bad_dpd_settings_on_update(self):
        """Failure tests of DPD settings for IPSec conn. during update.

        Note: On an update, the user may specify only some of the DPD settings.
        Previous values will be assigned for any missing items, so by the
        time the validation occurs, all items will be available for checking.
        The MTU may not be provided, during validation and will be ignored,
        if that is the case.
        """
        prev_connection = {'mtu': 2000,
                           'dpd_action': 'hold',
                           'dpd_interval': 100,
                           'dpd_timeout': 120}
        ipsec_sitecon = {'dpd': {'interval': 120}}
        self.validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon,
                                                              prev_connection)
        self.assertRaises(vpnaas.IPsecSiteConnectionDpdIntervalValueError,
                          self.validator.validate_ipsec_site_connection,
                          self.context, ipsec_sitecon, IPV4)

        prev_connection = {'mtu': 2000,
                           'dpd_action': 'hold',
                           'dpd_interval': 100,
                           'dpd_timeout': 120}
        ipsec_sitecon = {'dpd': {'timeout': 99}}
        self.validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon,
                                                              prev_connection)
        self.assertRaises(vpnaas.IPsecSiteConnectionDpdIntervalValueError,
                          self.validator.validate_ipsec_site_connection,
                          self.context, ipsec_sitecon, IPV4)

    def test_bad_mtu_for_ipsec_connection(self):
        """Failure test of invalid MTU values for IPSec conn create/update."""
        ip_version_limits = vpn_validator.VpnReferenceValidator.IP_MIN_MTU
        for version, limit in ip_version_limits.items():
            ipsec_sitecon = {'mtu': limit - 1,
                             'dpd_action': 'hold',
                             'dpd_interval': 100,
                             'dpd_timeout': 120}
            self.assertRaises(
                vpnaas.IPsecSiteConnectionMtuError,
                self.validator.validate_ipsec_site_connection,
                self.context, ipsec_sitecon, version)


class TestIPsecDriver(base.BaseTestCase):
    def setUp(self):
        super(TestIPsecDriver, self).setUp()
        mock.patch('neutron.common.rpc.create_connection').start()

        l3_agent = mock.Mock()
        l3_agent.host = FAKE_HOST
        plugin = mock.Mock()
        plugin.get_l3_agents_hosting_routers.return_value = [l3_agent]
        plugin_p = mock.patch('neutron.manager.NeutronManager.get_plugin')
        get_plugin = plugin_p.start()
        get_plugin.return_value = plugin
        service_plugin_p = mock.patch(
            'neutron.manager.NeutronManager.get_service_plugins')
        get_service_plugin = service_plugin_p.start()
        get_service_plugin.return_value = {constants.L3_ROUTER_NAT: plugin}

        service_plugin = mock.Mock()
        service_plugin.get_l3_agents_hosting_routers.return_value = [l3_agent]
        service_plugin._get_vpnservice.return_value = {
            'router_id': _uuid()
        }
        self.driver = ipsec_driver.IPsecVPNDriver(service_plugin)

    def _test_update(self, func, args):
        ctxt = n_ctx.Context('', 'somebody')
        with mock.patch.object(self.driver.agent_rpc, 'cast') as cast:
            func(ctxt, *args)
            cast.assert_called_once_with(
                ctxt,
                {'args': {},
                 'namespace': None,
                 'method': 'vpnservice_updated'},
                version='1.0',
                topic='ipsec_agent.fake_host')

    def test_create_ipsec_site_connection(self):
        self._test_update(self.driver.create_ipsec_site_connection,
                          [FAKE_VPN_CONNECTION])

    def test_update_ipsec_site_connection(self):
        self._test_update(self.driver.update_ipsec_site_connection,
                          [FAKE_VPN_CONNECTION, FAKE_VPN_CONNECTION])

    def test_delete_ipsec_site_connection(self):
        self._test_update(self.driver.delete_ipsec_site_connection,
                          [FAKE_VPN_CONNECTION])

    def test_update_vpnservice(self):
        self._test_update(self.driver.update_vpnservice,
                          [FAKE_VPN_SERVICE, FAKE_VPN_SERVICE])

    def test_delete_vpnservice(self):
        self._test_update(self.driver.delete_vpnservice,
                          [FAKE_VPN_SERVICE])

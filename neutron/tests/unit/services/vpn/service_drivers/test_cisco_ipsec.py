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

from neutron import context as n_ctx
from neutron.db import servicetype_db as st_db
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.services.vpn import plugin as vpn_plugin
from neutron.services.vpn.service_drivers import cisco_csr_db as csr_db
from neutron.services.vpn.service_drivers import cisco_ipsec as ipsec_driver
from neutron.services.vpn.service_drivers import cisco_validator as validator
from neutron.tests import base
from neutron.tests.unit import testlib_api

_uuid = uuidutils.generate_uuid

FAKE_VPN_CONN_ID = _uuid()
FAKE_VPN_CONNECTION = {
    'vpnservice_id': _uuid(),
    'id': FAKE_VPN_CONN_ID,
    'ikepolicy_id': _uuid(),
    'ipsecpolicy_id': _uuid(),
    'tenant_id': _uuid()
}

FAKE_SERVICE_ID = _uuid()
FAKE_VPN_CONNECTION = {
    'vpnservice_id': FAKE_SERVICE_ID
}

FAKE_ROUTER_ID = _uuid()
FAKE_VPN_SERVICE = {
    'router_id': FAKE_ROUTER_ID
}

FAKE_HOST = 'fake_host'
IPV4 = 4

CISCO_IPSEC_SERVICE_DRIVER = ('neutron.services.vpn.service_drivers.'
                              'cisco_ipsec.CiscoCsrIPsecVPNDriver')


class TestCiscoValidatorSelection(base.BaseTestCase):

    def setUp(self):
        super(TestCiscoValidatorSelection, self).setUp()
        vpnaas_provider = (constants.VPN + ':vpnaas:' +
                           CISCO_IPSEC_SERVICE_DRIVER + ':default')
        cfg.CONF.set_override('service_provider',
                              [vpnaas_provider],
                              'service_providers')
        stm = st_db.ServiceTypeManager()
        mock.patch('neutron.db.servicetype_db.ServiceTypeManager.get_instance',
                   return_value=stm).start()
        mock.patch('neutron.common.rpc.create_connection').start()
        self.vpn_plugin = vpn_plugin.VPNDriverPlugin()

    def test_reference_driver_used(self):
        self.assertIsInstance(self.vpn_plugin._get_validator(),
                              validator.CiscoCsrVpnValidator)


class TestCiscoIPsecDriverValidation(base.BaseTestCase):

    def setUp(self):
        super(TestCiscoIPsecDriverValidation, self).setUp()
        mock.patch('neutron.common.rpc.create_connection').start()
        self.l3_plugin = mock.Mock()
        mock.patch(
            'neutron.manager.NeutronManager.get_service_plugins',
            return_value={constants.L3_ROUTER_NAT: self.l3_plugin}).start()
        self.core_plugin = mock.Mock()
        mock.patch('neutron.manager.NeutronManager.get_plugin',
                   return_value=self.core_plugin).start()
        self.context = n_ctx.Context('some_user', 'some_tenant')
        self.vpn_service = {'router_id': '123'}
        self.router = mock.Mock()
        self.service_plugin = mock.Mock()
        self.validator = validator.CiscoCsrVpnValidator(self.service_plugin)

    def test_ike_version_unsupported(self):
        """Failure test that Cisco CSR REST API does not support IKE v2."""
        policy_info = {'ike_version': 'v2',
                       'lifetime': {'units': 'seconds', 'value': 60}}
        self.assertRaises(validator.CsrValidationFailure,
                          self.validator.validate_ike_version,
                          policy_info)

    def test_ike_lifetime_not_in_seconds(self):
        """Failure test of unsupported lifetime units for IKE policy."""
        policy_info = {'lifetime': {'units': 'kilobytes', 'value': 1000}}
        self.assertRaises(validator.CsrValidationFailure,
                          self.validator.validate_lifetime,
                          "IKE Policy", policy_info)

    def test_ipsec_lifetime_not_in_seconds(self):
        """Failure test of unsupported lifetime units for IPSec policy."""
        policy_info = {'lifetime': {'units': 'kilobytes', 'value': 1000}}
        self.assertRaises(validator.CsrValidationFailure,
                          self.validator.validate_lifetime,
                          "IPSec Policy", policy_info)

    def test_ike_lifetime_seconds_values_at_limits(self):
        """Test valid lifetime values for IKE policy."""
        policy_info = {'lifetime': {'units': 'seconds', 'value': 60}}
        self.validator.validate_lifetime('IKE Policy', policy_info)
        policy_info = {'lifetime': {'units': 'seconds', 'value': 86400}}
        self.validator.validate_lifetime('IKE Policy', policy_info)

    def test_ipsec_lifetime_seconds_values_at_limits(self):
        """Test valid lifetime values for IPSec policy."""
        policy_info = {'lifetime': {'units': 'seconds', 'value': 120}}
        self.validator.validate_lifetime('IPSec Policy', policy_info)
        policy_info = {'lifetime': {'units': 'seconds', 'value': 2592000}}
        self.validator.validate_lifetime('IPSec Policy', policy_info)

    def test_ike_lifetime_values_invalid(self):
        """Failure test of unsupported lifetime values for IKE policy."""
        which = "IKE Policy"
        policy_info = {'lifetime': {'units': 'seconds', 'value': 59}}
        self.assertRaises(validator.CsrValidationFailure,
                          self.validator.validate_lifetime,
                          which, policy_info)
        policy_info = {'lifetime': {'units': 'seconds', 'value': 86401}}
        self.assertRaises(validator.CsrValidationFailure,
                          self.validator.validate_lifetime,
                          which, policy_info)

    def test_ipsec_lifetime_values_invalid(self):
        """Failure test of unsupported lifetime values for IPSec policy."""
        which = "IPSec Policy"
        policy_info = {'lifetime': {'units': 'seconds', 'value': 119}}
        self.assertRaises(validator.CsrValidationFailure,
                          self.validator.validate_lifetime,
                          which, policy_info)
        policy_info = {'lifetime': {'units': 'seconds', 'value': 2592001}}
        self.assertRaises(validator.CsrValidationFailure,
                          self.validator.validate_lifetime,
                          which, policy_info)

    def test_ipsec_connection_with_mtu_at_limits(self):
        """Test IPSec site-to-site connection with MTU at limits."""
        conn_info = {'mtu': 1500}
        self.validator.validate_mtu(conn_info)
        conn_info = {'mtu': 9192}
        self.validator.validate_mtu(conn_info)

    def test_ipsec_connection_with_invalid_mtu(self):
        """Failure test of IPSec site connection with unsupported MTUs."""
        conn_info = {'mtu': 1499}
        self.assertRaises(validator.CsrValidationFailure,
                          self.validator.validate_mtu, conn_info)
        conn_info = {'mtu': 9193}
        self.assertRaises(validator.CsrValidationFailure,
                          self.validator.validate_mtu, conn_info)

    def simulate_gw_ip_available(self):
        """Helper function indicating that tunnel has a gateway IP."""
        def have_one():
            return 1
        self.router.gw_port.fixed_ips.__len__ = have_one
        ip_addr_mock = mock.Mock()
        self.router.gw_port.fixed_ips = [ip_addr_mock]

    def test_have_public_ip_for_router(self):
        """Ensure that router for IPSec connection has gateway IP."""
        self.simulate_gw_ip_available()
        try:
            self.validator.validate_public_ip_present(self.router)
        except Exception:
            self.fail("Unexpected exception on validation")

    def test_router_with_missing_gateway_ip(self):
        """Failure test of IPSec connection with missing gateway IP."""
        self.simulate_gw_ip_available()
        self.router.gw_port = None
        self.assertRaises(validator.CsrValidationFailure,
                          self.validator.validate_public_ip_present,
                          self.router)

    def test_peer_id_is_an_ip_address(self):
        """Ensure peer ID is an IP address for IPsec connection create."""
        ipsec_sitecon = {'peer_id': '10.10.10.10'}
        self.validator.validate_peer_id(ipsec_sitecon)

    def test_peer_id_is_not_ip_address(self):
        """Failure test of peer_id that is not an IP address."""
        ipsec_sitecon = {'peer_id': 'some-site.com'}
        self.assertRaises(validator.CsrValidationFailure,
                          self.validator.validate_peer_id, ipsec_sitecon)

    def test_validation_for_create_ipsec_connection(self):
        """Ensure all validation passes for IPSec site connection create."""
        self.simulate_gw_ip_available()
        self.service_plugin.get_ikepolicy = mock.Mock(
            return_value={'ike_version': 'v1',
                          'lifetime': {'units': 'seconds', 'value': 60}})
        self.service_plugin.get_ipsecpolicy = mock.Mock(
            return_value={'lifetime': {'units': 'seconds', 'value': 120}})
        self.service_plugin.get_vpnservice = mock.Mock(
            return_value=self.vpn_service)
        self.l3_plugin._get_router = mock.Mock(return_value=self.router)
        # Provide the minimum needed items to validate
        ipsec_sitecon = {'id': '1',
                         'vpnservice_id': FAKE_SERVICE_ID,
                         'ikepolicy_id': '123',
                         'ipsecpolicy_id': '2',
                         'mtu': 1500,
                         'peer_id': '10.10.10.10'}
        # Using defaults for DPD info
        expected = {'dpd_action': 'hold',
                    'dpd_interval': 30,
                    'dpd_timeout': 120}
        expected.update(ipsec_sitecon)
        self.validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon)
        self.validator.validate_ipsec_site_connection(self.context,
                                                      ipsec_sitecon, IPV4)
        self.assertEqual(expected, ipsec_sitecon)


class TestCiscoIPsecDriverMapping(base.BaseTestCase):

    def setUp(self):
        super(TestCiscoIPsecDriverMapping, self).setUp()
        self.context = mock.patch.object(n_ctx, 'Context').start()
        self.session = self.context.session
        self.query_mock = self.session.query.return_value.order_by

    def test_identifying_first_mapping_id(self):
        """Make sure first available ID is obtained for each ID type."""
        # Simulate mapping table is empty - get first one
        self.query_mock.return_value = []
        next_id = csr_db.get_next_available_tunnel_id(self.session)
        self.assertEqual(0, next_id)

        next_id = csr_db.get_next_available_ike_policy_id(self.session)
        self.assertEqual(1, next_id)

        next_id = csr_db.get_next_available_ipsec_policy_id(self.session)
        self.assertEqual(1, next_id)

    def test_last_mapping_id_available(self):
        """Make sure can get the last ID for each of the table types."""
        # Simulate query indicates table is full
        self.query_mock.return_value = [
            (x, ) for x in xrange(csr_db.MAX_CSR_TUNNELS - 1)]
        next_id = csr_db.get_next_available_tunnel_id(self.session)
        self.assertEqual(csr_db.MAX_CSR_TUNNELS - 1, next_id)

        self.query_mock.return_value = [
            (x, ) for x in xrange(1, csr_db.MAX_CSR_IKE_POLICIES)]
        next_id = csr_db.get_next_available_ike_policy_id(self.session)
        self.assertEqual(csr_db.MAX_CSR_IKE_POLICIES, next_id)

        self.query_mock.return_value = [
            (x, ) for x in xrange(1, csr_db.MAX_CSR_IPSEC_POLICIES)]
        next_id = csr_db.get_next_available_ipsec_policy_id(self.session)
        self.assertEqual(csr_db.MAX_CSR_IPSEC_POLICIES, next_id)

    def test_reusing_first_available_mapping_id(self):
        """Ensure that we reuse the first available ID.

        Make sure that the next lowest ID is obtained from the mapping
        table when there are "holes" from deletions. Database query sorts
        the entries, so will return them in order. Using tunnel ID, as the
        logic is the same for each ID type.
        """
        self.query_mock.return_value = [(0, ), (1, ), (2, ), (5, ), (6, )]
        next_id = csr_db.get_next_available_tunnel_id(self.session)
        self.assertEqual(3, next_id)

    def test_no_more_mapping_ids_available(self):
        """Failure test of trying to reserve ID, when none available."""
        self.query_mock.return_value = [
            (x, ) for x in xrange(csr_db.MAX_CSR_TUNNELS)]
        self.assertRaises(IndexError, csr_db.get_next_available_tunnel_id,
                          self.session)

        self.query_mock.return_value = [
            (x, ) for x in xrange(1, csr_db.MAX_CSR_IKE_POLICIES + 1)]
        self.assertRaises(IndexError, csr_db.get_next_available_ike_policy_id,
                          self.session)

        self.query_mock.return_value = [
            (x, ) for x in xrange(1, csr_db.MAX_CSR_IPSEC_POLICIES + 1)]
        self.assertRaises(IndexError,
                          csr_db.get_next_available_ipsec_policy_id,
                          self.session)

    def test_create_tunnel_mappings(self):
        """Ensure successfully create new tunnel mappings."""
        # Simulate that first IDs are obtained
        self.query_mock.return_value = []
        map_db_mock = mock.patch.object(csr_db, 'IdentifierMap').start()
        conn_info = {'ikepolicy_id': '10',
                     'ipsecpolicy_id': '50',
                     'id': '100',
                     'tenant_id': '1000'}
        csr_db.create_tunnel_mapping(self.context, conn_info)
        map_db_mock.assert_called_once_with(csr_tunnel_id=0,
                                            csr_ike_policy_id=1,
                                            csr_ipsec_policy_id=1,
                                            ipsec_site_conn_id='100',
                                            tenant_id='1000')
        # Create another, with next ID of 2 for all IDs (not mocking each
        # ID separately, so will not have different IDs).
        self.query_mock.return_value = [(0, ), (1, )]
        map_db_mock.reset_mock()
        conn_info = {'ikepolicy_id': '20',
                     'ipsecpolicy_id': '60',
                     'id': '101',
                     'tenant_id': '1000'}
        csr_db.create_tunnel_mapping(self.context, conn_info)
        map_db_mock.assert_called_once_with(csr_tunnel_id=2,
                                            csr_ike_policy_id=2,
                                            csr_ipsec_policy_id=2,
                                            ipsec_site_conn_id='101',
                                            tenant_id='1000')


class TestCiscoIPsecDriver(testlib_api.SqlTestCase):

    """Test that various incoming requests are sent to device driver."""

    def setUp(self):
        super(TestCiscoIPsecDriver, self).setUp()
        mock.patch('neutron.common.rpc.create_connection').start()

        service_plugin = mock.Mock()
        service_plugin.get_host_for_router.return_value = FAKE_HOST
        # TODO(pcm): Remove when Cisco L3 router plugin support available
        mock.patch('neutron.services.vpn.service_drivers.'
                   'cisco_cfg_loader.get_host_for_router',
                   return_value=FAKE_HOST).start()
        service_plugin._get_vpnservice.return_value = {
            'router_id': _uuid()
        }
        get_service_plugin = mock.patch(
            'neutron.manager.NeutronManager.get_service_plugins').start()
        get_service_plugin.return_value = {
            constants.L3_ROUTER_NAT: service_plugin}
        self.driver = ipsec_driver.CiscoCsrIPsecVPNDriver(service_plugin)
        mock.patch.object(csr_db, 'create_tunnel_mapping').start()
        self.context = n_ctx.Context('some_user', 'some_tenant')

    def _test_update(self, func, args, additional_info=None):
        with mock.patch.object(self.driver.agent_rpc, 'cast') as cast:
            func(self.context, *args)
            cast.assert_called_once_with(
                self.context,
                {'args': additional_info,
                 'namespace': None,
                 'method': 'vpnservice_updated'},
                version='1.0',
                topic='cisco_csr_ipsec_agent.fake_host')

    def test_create_ipsec_site_connection(self):
        self._test_update(self.driver.create_ipsec_site_connection,
                          [FAKE_VPN_CONNECTION],
                          {'reason': 'ipsec-conn-create'})

    def test_update_ipsec_site_connection(self):
        self._test_update(self.driver.update_ipsec_site_connection,
                          [FAKE_VPN_CONNECTION, FAKE_VPN_CONNECTION],
                          {'reason': 'ipsec-conn-update'})

    def test_delete_ipsec_site_connection(self):
        self._test_update(self.driver.delete_ipsec_site_connection,
                          [FAKE_VPN_CONNECTION],
                          {'reason': 'ipsec-conn-delete'})

    def test_update_vpnservice(self):
        self._test_update(self.driver.update_vpnservice,
                          [FAKE_VPN_SERVICE, FAKE_VPN_SERVICE],
                          {'reason': 'vpn-service-update'})

    def test_delete_vpnservice(self):
        self._test_update(self.driver.delete_vpnservice,
                          [FAKE_VPN_SERVICE],
                          {'reason': 'vpn-service-delete'})

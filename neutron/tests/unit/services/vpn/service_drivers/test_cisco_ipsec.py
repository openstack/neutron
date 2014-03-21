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


from neutron import context as n_ctx
from neutron.db import api as dbapi
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.services.vpn.service_drivers import cisco_csr_db as csr_db
from neutron.services.vpn.service_drivers import cisco_ipsec as ipsec_driver
from neutron.tests import base

_uuid = uuidutils.generate_uuid

FAKE_VPN_CONN_ID = _uuid()

FAKE_VPN_CONNECTION = {
    'vpnservice_id': _uuid(),
    'id': FAKE_VPN_CONN_ID,
    'ikepolicy_id': _uuid(),
    'ipsecpolicy_id': _uuid(),
    'tenant_id': _uuid()
}
FAKE_VPN_SERVICE = {
    'router_id': _uuid()
}
FAKE_HOST = 'fake_host'


class TestCiscoIPsecDriverValidation(base.BaseTestCase):

    def setUp(self):
        super(TestCiscoIPsecDriverValidation, self).setUp()
        mock.patch('neutron.openstack.common.rpc.create_connection').start()
        self.service_plugin = mock.Mock()
        self.driver = ipsec_driver.CiscoCsrIPsecVPNDriver(self.service_plugin)
        self.context = n_ctx.Context('some_user', 'some_tenant')
        self.vpn_service = mock.Mock()

    def test_ike_version_unsupported(self):
        """Failure test that Cisco CSR REST API does not support IKE v2."""
        policy_info = {'ike_version': 'v2',
                       'lifetime': {'units': 'seconds', 'value': 60}}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_ike_version, policy_info)

    def test_ike_lifetime_not_in_seconds(self):
        """Failure test of unsupported lifetime units for IKE policy."""
        policy_info = {'lifetime': {'units': 'kilobytes', 'value': 1000}}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_lifetime,
                          "IKE Policy", policy_info)

    def test_ipsec_lifetime_not_in_seconds(self):
        """Failure test of unsupported lifetime units for IPSec policy."""
        policy_info = {'lifetime': {'units': 'kilobytes', 'value': 1000}}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_lifetime,
                          "IPSec Policy", policy_info)

    def test_ike_lifetime_seconds_values_at_limits(self):
        """Test valid lifetime values for IKE policy."""
        policy_info = {'lifetime': {'units': 'seconds', 'value': 60}}
        self.driver.validate_lifetime('IKE Policy', policy_info)
        policy_info = {'lifetime': {'units': 'seconds', 'value': 86400}}
        self.driver.validate_lifetime('IKE Policy', policy_info)

    def test_ipsec_lifetime_seconds_values_at_limits(self):
        """Test valid lifetime values for IPSec policy."""
        policy_info = {'lifetime': {'units': 'seconds', 'value': 120}}
        self.driver.validate_lifetime('IPSec Policy', policy_info)
        policy_info = {'lifetime': {'units': 'seconds', 'value': 2592000}}
        self.driver.validate_lifetime('IPSec Policy', policy_info)

    def test_ike_lifetime_values_invalid(self):
        """Failure test of unsupported lifetime values for IKE policy."""
        which = "IKE Policy"
        policy_info = {'lifetime': {'units': 'seconds', 'value': 59}}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_lifetime,
                          which, policy_info)
        policy_info = {'lifetime': {'units': 'seconds', 'value': 86401}}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_lifetime,
                          which, policy_info)

    def test_ipsec_lifetime_values_invalid(self):
        """Failure test of unsupported lifetime values for IPSec policy."""
        which = "IPSec Policy"
        policy_info = {'lifetime': {'units': 'seconds', 'value': 119}}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_lifetime,
                          which, policy_info)
        policy_info = {'lifetime': {'units': 'seconds', 'value': 2592001}}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_lifetime,
                          which, policy_info)

    def test_ipsec_connection_with_mtu_at_limits(self):
        """Test IPSec site-to-site connection with MTU at limits."""
        conn_info = {'mtu': 1500}
        self.driver.validate_mtu(conn_info)
        conn_info = {'mtu': 9192}
        self.driver.validate_mtu(conn_info)

    def test_ipsec_connection_with_invalid_mtu(self):
        """Failure test of IPSec site connection with unsupported MTUs."""
        conn_info = {'mtu': 1499}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_mtu, conn_info)
        conn_info = {'mtu': 9193}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_mtu, conn_info)

    def simulate_gw_ip_available(self):
        """Helper function indicating that tunnel has a gateway IP."""
        def have_one():
            return 1
        self.vpn_service.router.gw_port.fixed_ips.__len__ = have_one
        ip_addr_mock = mock.Mock()
        self.vpn_service.router.gw_port.fixed_ips = [ip_addr_mock]
        return ip_addr_mock

    def test_have_public_ip_for_router(self):
        """Ensure that router for IPSec connection has gateway IP."""
        self.simulate_gw_ip_available()
        self.driver.validate_public_ip_present(self.vpn_service)

    def test_router_with_missing_gateway_ip(self):
        """Failure test of IPSec connection with missing gateway IP."""
        self.simulate_gw_ip_available()
        self.vpn_service.router.gw_port = None
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_public_ip_present,
                          self.vpn_service)

    def test_peer_id_is_an_ip_address(self):
        """Ensure peer ID is an IP address for IPsec connection create."""
        ipsec_conn = {'peer_id': '10.10.10.10'}
        self.driver.validate_peer_id(ipsec_conn)

    def test_peer_id_is_not_ip_address(self):
        """Failure test of peer_id that is not an IP address."""
        ipsec_conn = {'peer_id': 'some-site.com'}
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.validate_peer_id, ipsec_conn)

    def test_validation_for_create_ipsec_connection(self):
        """Ensure all validation passes for IPSec site connection create."""
        self.simulate_gw_ip_available()
        # Provide the minimum needed items to validate
        ipsec_conn = {'id': '1',
                      'ikepolicy_id': '123',
                      'ipsecpolicy_id': '2',
                      'mtu': 1500,
                      'peer_id': '10.10.10.10'}
        self.service_plugin.get_ikepolicy = mock.Mock(
            return_value={'ike_version': 'v1',
                          'lifetime': {'units': 'seconds', 'value': 60}})
        self.service_plugin.get_ipsecpolicy = mock.Mock(
            return_value={'lifetime': {'units': 'seconds', 'value': 120}})
        self.driver.validate_ipsec_connection(self.context, ipsec_conn,
                                              self.vpn_service)


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


class TestCiscoIPsecDriver(base.BaseTestCase):

    """Test that various incoming requests are sent to device driver."""

    def setUp(self):
        super(TestCiscoIPsecDriver, self).setUp()
        dbapi.configure_db()
        self.addCleanup(dbapi.clear_db)
        mock.patch('neutron.openstack.common.rpc.create_connection').start()

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
        self.db_update_mock = service_plugin.update_ipsec_site_conn_status
        self.driver = ipsec_driver.CiscoCsrIPsecVPNDriver(service_plugin)
        self.driver.validate_ipsec_connection = mock.Mock()
        mock.patch.object(csr_db, 'create_tunnel_mapping').start()
        self.context = n_ctx.Context('some_user', 'some_tenant')

    def _test_update(self, func, args, reason=None):
        with mock.patch.object(self.driver.agent_rpc, 'cast') as cast:
            func(self.context, *args)
            cast.assert_called_once_with(
                self.context,
                {'args': reason,
                 'namespace': None,
                 'method': 'vpnservice_updated'},
                version='1.0',
                topic='cisco_csr_ipsec_agent.fake_host')

    def test_create_ipsec_site_connection(self):
        self._test_update(self.driver.create_ipsec_site_connection,
                          [FAKE_VPN_CONNECTION],
                          {'reason': 'ipsec-conn-create'})

    def test_failure_validation_ipsec_connection(self):
        """Failure test of validation during IPSec site connection create.

        Simulate a validation failure, and ensure that database is
        updated to indicate connection is in error state.

        TODO(pcm): FUTURE - remove test case, once vendor plugin
        validation is done before database commit.
        """
        self.driver.validate_ipsec_connection.side_effect = (
            ipsec_driver.CsrValidationFailure(resource='IPSec Connection',
                                              key='mtu', value=1000))
        self.assertRaises(ipsec_driver.CsrValidationFailure,
                          self.driver.create_ipsec_site_connection,
                          self.context, FAKE_VPN_CONNECTION)
        self.db_update_mock.assert_called_with(self.context,
                                               FAKE_VPN_CONN_ID,
                                               constants.ERROR)

    def test_update_ipsec_site_connection(self):
        # TODO(pcm) FUTURE - Update test, when supported
        self.assertRaises(ipsec_driver.CsrUnsupportedError,
                          self._test_update,
                          self.driver.update_ipsec_site_connection,
                          [FAKE_VPN_CONNECTION, FAKE_VPN_CONNECTION])

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

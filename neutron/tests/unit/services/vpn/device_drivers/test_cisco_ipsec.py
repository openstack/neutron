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

import copy
import httplib
import operator

import mock

from neutron import context
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.services.vpn.device_drivers import (
    cisco_csr_rest_client as csr_client)
from neutron.services.vpn.device_drivers import cisco_ipsec as ipsec_driver
from neutron.tests import base

_uuid = uuidutils.generate_uuid
FAKE_HOST = 'fake_host'
FAKE_ROUTER_ID = _uuid()
FAKE_VPN_SERVICE = {
    'id': _uuid(),
    'router_id': FAKE_ROUTER_ID,
    'admin_state_up': True,
    'status': constants.PENDING_CREATE,
    'subnet': {'cidr': '10.0.0.0/24'},
    'ipsec_site_connections': [
        {'peer_cidrs': ['20.0.0.0/24',
                        '30.0.0.0/24']},
        {'peer_cidrs': ['40.0.0.0/24',
                        '50.0.0.0/24']}]
}
FIND_CFG_FOR_CSRS = ('neutron.services.vpn.device_drivers.cisco_ipsec.'
                     'find_available_csrs_from_config')


class TestCiscoCsrIPSecConnection(base.BaseTestCase):
    def setUp(self):
        super(TestCiscoCsrIPSecConnection, self).setUp()
        self.conn_info = {
            u'id': '123',
            u'status': constants.PENDING_CREATE,
            u'admin_state_up': True,
            'psk': 'secret',
            'peer_address': '192.168.1.2',
            'peer_cidrs': ['10.1.0.0/24', '10.2.0.0/24'],
            'mtu': 1500,
            'ike_policy': {'auth_algorithm': 'sha1',
                           'encryption_algorithm': 'aes-128',
                           'pfs': 'Group5',
                           'ike_version': 'v1',
                           'lifetime_units': 'seconds',
                           'lifetime_value': 3600},
            'ipsec_policy': {'transform_protocol': 'ah',
                             'encryption_algorithm': 'aes-128',
                             'auth_algorithm': 'sha1',
                             'pfs': 'group5',
                             'lifetime_units': 'seconds',
                             'lifetime_value': 3600},
            'cisco': {'site_conn_id': 'Tunnel0',
                      'ike_policy_id': 222,
                      'ipsec_policy_id': 333,
                      'router_public_ip': '172.24.4.23'}
        }
        self.csr = mock.Mock(spec=csr_client.CsrRestClient)
        self.csr.status = 201  # All calls to CSR REST API succeed
        self.csr.tunnel_ip = '172.24.4.23'
        self.ipsec_conn = ipsec_driver.CiscoCsrIPSecConnection(self.conn_info,
                                                               self.csr)

    def test_create_ipsec_site_connection(self):
        """Ensure all steps are done to create an IPSec site connection.

        Verify that each of the driver calls occur (in order), and
        the right information is stored for later deletion.
        """
        expected = ['create_pre_shared_key',
                    'create_ike_policy',
                    'create_ipsec_policy',
                    'create_ipsec_connection',
                    'create_static_route',
                    'create_static_route']
        expected_rollback_steps = [
            ipsec_driver.RollbackStep(action='pre_shared_key',
                                      resource_id='123',
                                      title='Pre-Shared Key'),
            ipsec_driver.RollbackStep(action='ike_policy',
                                      resource_id=222,
                                      title='IKE Policy'),
            ipsec_driver.RollbackStep(action='ipsec_policy',
                                      resource_id=333,
                                      title='IPSec Policy'),
            ipsec_driver.RollbackStep(action='ipsec_connection',
                                      resource_id='Tunnel0',
                                      title='IPSec Connection'),
            ipsec_driver.RollbackStep(action='static_route',
                                      resource_id='10.1.0.0_24_Tunnel0',
                                      title='Static Route'),
            ipsec_driver.RollbackStep(action='static_route',
                                      resource_id='10.2.0.0_24_Tunnel0',
                                      title='Static Route')]
        self.ipsec_conn.create_ipsec_site_connection(mock.Mock(),
                                                     self.conn_info)
        client_calls = [c[0] for c in self.csr.method_calls]
        self.assertEqual(expected, client_calls)
        self.assertEqual(expected_rollback_steps, self.ipsec_conn.steps)

    def test_create_ipsec_site_connection_with_rollback(self):
        """Failure test of IPSec site conn creation that fails and rolls back.

        Simulate a failure in the last create step (making routes for the
        peer networks), and ensure that the create steps are called in
        order (except for create_static_route), and that the delete
        steps are called in reverse order. At the end, there should be no
        rollback infromation for the connection.
        """
        def fake_route_check_fails(*args, **kwargs):
            if args[0] == 'Static Route':
                # So that subsequent calls to CSR rest client (for rollback)
                # will fake as passing.
                self.csr.status = httplib.NO_CONTENT
                raise ipsec_driver.CsrResourceCreateFailure(resource=args[0],
                                                            which=args[1])

        with mock.patch.object(ipsec_driver.CiscoCsrIPSecConnection,
                               '_check_create',
                               side_effect=fake_route_check_fails):

            expected = ['create_pre_shared_key',
                        'create_ike_policy',
                        'create_ipsec_policy',
                        'create_ipsec_connection',
                        'create_static_route',
                        'delete_ipsec_connection',
                        'delete_ipsec_policy',
                        'delete_ike_policy',
                        'delete_pre_shared_key']
            self.ipsec_conn.create_ipsec_site_connection(mock.Mock(),
                                                         self.conn_info)
            client_calls = [c[0] for c in self.csr.method_calls]
            self.assertEqual(expected, client_calls)
            self.assertEqual([], self.ipsec_conn.steps)

    def test_create_verification_with_error(self):
        """Negative test of create check step had failed."""
        self.csr.status = httplib.NOT_FOUND
        self.assertRaises(ipsec_driver.CsrResourceCreateFailure,
                          self.ipsec_conn._check_create, 'name', 'id')

    def test_failure_with_invalid_create_step(self):
        """Negative test of invalid create step (programming error)."""
        self.ipsec_conn.steps = []
        try:
            self.ipsec_conn.do_create_action('bogus', None, '123', 'Bad Step')
        except ipsec_driver.CsrResourceCreateFailure:
            pass
        else:
            self.fail('Expected exception with invalid create step')

    def test_failure_with_invalid_delete_step(self):
        """Negative test of invalid delete step (programming error)."""
        self.ipsec_conn.steps = [ipsec_driver.RollbackStep(action='bogus',
                                                           resource_id='123',
                                                           title='Bogus Step')]
        try:
            self.ipsec_conn.do_rollback()
        except ipsec_driver.CsrResourceCreateFailure:
            pass
        else:
            self.fail('Expected exception with invalid delete step')

    def test_delete_ipsec_connection(self):
        """Perform delete of IPSec site connection and check steps done."""
        # Simulate that a create was done with rollback steps stored
        self.ipsec_conn.steps = [
            ipsec_driver.RollbackStep(action='pre_shared_key',
                                      resource_id='123',
                                      title='Pre-Shared Key'),
            ipsec_driver.RollbackStep(action='ike_policy',
                                      resource_id=222,
                                      title='IKE Policy'),
            ipsec_driver.RollbackStep(action='ipsec_policy',
                                      resource_id=333,
                                      title='IPSec Policy'),
            ipsec_driver.RollbackStep(action='ipsec_connection',
                                      resource_id='Tunnel0',
                                      title='IPSec Connection'),
            ipsec_driver.RollbackStep(action='static_route',
                                      resource_id='10.1.0.0_24_Tunnel0',
                                      title='Static Route'),
            ipsec_driver.RollbackStep(action='static_route',
                                      resource_id='10.2.0.0_24_Tunnel0',
                                      title='Static Route')]
        expected = ['delete_static_route',
                    'delete_static_route',
                    'delete_ipsec_connection',
                    'delete_ipsec_policy',
                    'delete_ike_policy',
                    'delete_pre_shared_key']
        self.ipsec_conn.delete_ipsec_site_connection(mock.Mock(), 123)
        client_calls = [c[0] for c in self.csr.method_calls]
        self.assertEqual(expected, client_calls)


class TestCiscoCsrIPsecConnectionCreateTransforms(base.BaseTestCase):

    """Verifies that config info is prepared/transformed correctly."""

    def setUp(self):
        super(TestCiscoCsrIPsecConnectionCreateTransforms, self).setUp()
        self.conn_info = {
            u'id': '123',
            u'status': constants.PENDING_CREATE,
            u'admin_state_up': True,
            'psk': 'secret',
            'peer_address': '192.168.1.2',
            'peer_cidrs': ['10.1.0.0/24', '10.2.0.0/24'],
            'mtu': 1500,
            'ike_policy': {'auth_algorithm': 'sha1',
                           'encryption_algorithm': 'aes-128',
                           'pfs': 'Group5',
                           'ike_version': 'v1',
                           'lifetime_units': 'seconds',
                           'lifetime_value': 3600},
            'ipsec_policy': {'transform_protocol': 'ah',
                             'encryption_algorithm': 'aes-128',
                             'auth_algorithm': 'sha1',
                             'pfs': 'group5',
                             'lifetime_units': 'seconds',
                             'lifetime_value': 3600},
            'cisco': {'site_conn_id': 'Tunnel0',
                      'ike_policy_id': 222,
                      'ipsec_policy_id': 333,
                      'router_public_ip': '172.24.4.23'}
        }
        self.csr = mock.Mock(spec=csr_client.CsrRestClient)
        self.csr.tunnel_ip = '172.24.4.23'
        self.ipsec_conn = ipsec_driver.CiscoCsrIPSecConnection(self.conn_info,
                                                               self.csr)

    def test_invalid_attribute(self):
        """Negative test of unknown attribute - programming error."""
        self.assertRaises(ipsec_driver.CsrDriverMismatchError,
                          self.ipsec_conn.translate_dialect,
                          'ike_policy', 'unknown_attr', self.conn_info)

    def test_driver_unknown_mapping(self):
        """Negative test of service driver providing unknown value to map."""
        self.conn_info['ike_policy']['pfs'] = "unknown_value"
        self.assertRaises(ipsec_driver.CsrUnknownMappingError,
                          self.ipsec_conn.translate_dialect,
                          'ike_policy', 'pfs', self.conn_info['ike_policy'])

    def test_psk_create_info(self):
        """Ensure that pre-shared key info is created correctly."""
        expected = {u'keyring-name': '123',
                    u'pre-shared-key-list': [
                        {u'key': 'secret',
                         u'encrypted': False,
                         u'peer-address': '192.168.1.2'}]}
        psk_id = self.conn_info['id']
        psk_info = self.ipsec_conn.create_psk_info(psk_id, self.conn_info)
        self.assertEqual(expected, psk_info)

    def test_create_ike_policy_info(self):
        """Ensure that IKE policy info is mapped/created correctly."""
        expected = {u'priority-id': 222,
                    u'encryption': u'aes',
                    u'hash': u'sha',
                    u'dhGroup': 5,
                    u'version': u'v1',
                    u'lifetime': 3600}
        policy_id = self.conn_info['cisco']['ike_policy_id']
        policy_info = self.ipsec_conn.create_ike_policy_info(policy_id,
                                                             self.conn_info)
        self.assertEqual(expected, policy_info)

    def test_create_ike_policy_info_different_encryption(self):
        """Ensure that IKE policy info is mapped/created correctly."""
        self.conn_info['ike_policy']['encryption_algorithm'] = 'aes-192'
        expected = {u'priority-id': 222,
                    u'encryption': u'aes192',
                    u'hash': u'sha',
                    u'dhGroup': 5,
                    u'version': u'v1',
                    u'lifetime': 3600}
        policy_id = self.conn_info['cisco']['ike_policy_id']
        policy_info = self.ipsec_conn.create_ike_policy_info(policy_id,
                                                             self.conn_info)
        self.assertEqual(expected, policy_info)

    def test_create_ike_policy_info_non_defaults(self):
        """Ensure that IKE policy info with different values."""
        self.conn_info['ike_policy'] = {
            'auth_algorithm': 'sha1',
            'encryption_algorithm': 'aes-256',
            'pfs': 'Group14',
            'ike_version': 'v1',
            'lifetime_units': 'seconds',
            'lifetime_value': 60
        }
        expected = {u'priority-id': 222,
                    u'encryption': u'aes256',
                    u'hash': u'sha',
                    u'dhGroup': 14,
                    u'version': u'v1',
                    u'lifetime': 60}
        policy_id = self.conn_info['cisco']['ike_policy_id']
        policy_info = self.ipsec_conn.create_ike_policy_info(policy_id,
                                                             self.conn_info)
        self.assertEqual(expected, policy_info)

    def test_ipsec_policy_info(self):
        """Ensure that IPSec policy info is mapped/created correctly.

        Note: That although the default for anti-replay-window-size on the
        CSR is 64, we force it to disabled, for OpenStack use.
        """
        expected = {u'policy-id': 333,
                    u'protection-suite': {
                        u'esp-encryption': u'esp-aes',
                        u'esp-authentication': u'esp-sha-hmac',
                        u'ah': u'ah-sha-hmac'
                    },
                    u'lifetime-sec': 3600,
                    u'pfs': u'group5',
                    u'anti-replay-window-size': u'disable'}
        ipsec_policy_id = self.conn_info['cisco']['ipsec_policy_id']
        policy_info = self.ipsec_conn.create_ipsec_policy_info(ipsec_policy_id,
                                                               self.conn_info)
        self.assertEqual(expected, policy_info)

    def test_ipsec_policy_info_different_encryption(self):
        """Create IPSec policy with different settings."""
        self.conn_info['ipsec_policy']['transform_protocol'] = 'ah-esp'
        self.conn_info['ipsec_policy']['encryption_algorithm'] = 'aes-192'
        expected = {u'policy-id': 333,
                    u'protection-suite': {
                        u'esp-encryption': u'esp-192-aes',
                        u'esp-authentication': u'esp-sha-hmac',
                        u'ah': u'ah-sha-hmac'
                    },
                    u'lifetime-sec': 3600,
                    u'pfs': u'group5',
                    u'anti-replay-window-size': u'disable'}
        ipsec_policy_id = self.conn_info['cisco']['ipsec_policy_id']
        policy_info = self.ipsec_conn.create_ipsec_policy_info(ipsec_policy_id,
                                                               self.conn_info)
        self.assertEqual(expected, policy_info)

    def test_ipsec_policy_info_non_defaults(self):
        """Create/map IPSec policy info with different values."""
        self.conn_info['ipsec_policy'] = {'transform_protocol': 'esp',
                                          'encryption_algorithm': '3des',
                                          'auth_algorithm': 'sha1',
                                          'pfs': 'group14',
                                          'lifetime_units': 'seconds',
                                          'lifetime_value': 120,
                                          'anti-replay-window-size': 'disable'}
        expected = {u'policy-id': 333,
                    u'protection-suite': {
                        u'esp-encryption': u'esp-3des',
                        u'esp-authentication': u'esp-sha-hmac'
                    },
                    u'lifetime-sec': 120,
                    u'pfs': u'group14',
                    u'anti-replay-window-size': u'disable'}
        ipsec_policy_id = self.conn_info['cisco']['ipsec_policy_id']
        policy_info = self.ipsec_conn.create_ipsec_policy_info(ipsec_policy_id,
                                                               self.conn_info)
        self.assertEqual(expected, policy_info)

    def test_site_connection_info(self):
        """Ensure site-to-site connection info is created/mapped correctly."""
        expected = {u'vpn-interface-name': 'Tunnel0',
                    u'ipsec-policy-id': 333,
                    u'remote-device': {
                        u'tunnel-ip-address': '192.168.1.2'
                    },
                    u'mtu': 1500}
        ipsec_policy_id = self.conn_info['cisco']['ipsec_policy_id']
        site_conn_id = self.conn_info['cisco']['site_conn_id']
        conn_info = self.ipsec_conn.create_site_connection_info(
            site_conn_id, ipsec_policy_id, self.conn_info)
        self.assertEqual(expected, conn_info)

    def test_static_route_info(self):
        """Create static route info for peer CIDRs."""
        expected = [('10.1.0.0_24_Tunnel0',
                     {u'destination-network': '10.1.0.0/24',
                      u'outgoing-interface': 'Tunnel0'}),
                    ('10.2.0.0_24_Tunnel0',
                     {u'destination-network': '10.2.0.0/24',
                      u'outgoing-interface': 'Tunnel0'})]
#         self.driver.csr.make_route_id.side_effect = ['10.1.0.0_24_Tunnel0',
#                                                      '10.2.0.0_24_Tunnel0']
        site_conn_id = self.conn_info['cisco']['site_conn_id']
        routes_info = self.ipsec_conn.create_routes_info(site_conn_id,
                                                         self.conn_info)
        self.assertEqual(2, len(routes_info))
        self.assertEqual(expected, routes_info)


class TestCiscoCsrIPsecDeviceDriverSyncStatuses(base.BaseTestCase):

    """Test status/state of services and connections, after sync."""

    def setUp(self):
        super(TestCiscoCsrIPsecDeviceDriverSyncStatuses, self).setUp()
        for klass in ['neutron.common.rpc.create_connection',
                      'neutron.context.get_admin_context_without_session',
                      'neutron.openstack.common.'
                      'loopingcall.FixedIntervalLoopingCall']:
            mock.patch(klass).start()
        self.context = context.Context('some_user', 'some_tenant')
        self.agent = mock.Mock()
        self.driver = ipsec_driver.CiscoCsrIPsecDriver(self.agent, FAKE_HOST)
        self.driver.agent_rpc = mock.Mock()
        self.conn_create = mock.patch.object(
            ipsec_driver.CiscoCsrIPSecConnection,
            'create_ipsec_site_connection').start()
        self.conn_delete = mock.patch.object(
            ipsec_driver.CiscoCsrIPSecConnection,
            'delete_ipsec_site_connection').start()
        self.admin_state = mock.patch.object(
            ipsec_driver.CiscoCsrIPSecConnection,
            'set_admin_state').start()
        self.csr = mock.Mock()
        self.router_info = {u'router_info': {'rest_mgmt_ip': '2.2.2.2',
                                             'tunnel_ip': '1.1.1.3',
                                             'username': 'me',
                                             'password': 'password',
                                             'timeout': 120,
                                             'external_ip': u'1.1.1.1'}}
        self.service123_data = {u'id': u'123',
                                u'status': constants.DOWN,
                                u'admin_state_up': False}
        self.service123_data.update(self.router_info)
        self.conn1_data = {u'id': u'1',
                           u'status': constants.ACTIVE,
                           u'admin_state_up': True,
                           u'mtu': 1500,
                           u'psk': u'secret',
                           u'peer_address': '192.168.1.2',
                           u'peer_cidrs': ['10.1.0.0/24', '10.2.0.0/24'],
                           u'ike_policy': {
                               u'auth_algorithm': u'sha1',
                               u'encryption_algorithm': u'aes-128',
                               u'pfs': u'Group5',
                               u'ike_version': u'v1',
                               u'lifetime_units': u'seconds',
                               u'lifetime_value': 3600},
                           u'ipsec_policy': {
                               u'transform_protocol': u'ah',
                               u'encryption_algorithm': u'aes-128',
                               u'auth_algorithm': u'sha1',
                               u'pfs': u'group5',
                               u'lifetime_units': u'seconds',
                               u'lifetime_value': 3600},
                           u'cisco': {u'site_conn_id': u'Tunnel0'}}

    # NOTE: For sync, there is mark (trivial), update (tested),
    # sweep (tested), and report(tested) phases.

    def test_update_ipsec_connection_create_notify(self):
        """Notified of connection create request - create."""
        # Make the (existing) service
        self.driver.create_vpn_service(self.service123_data)
        conn_data = copy.deepcopy(self.conn1_data)
        conn_data[u'status'] = constants.PENDING_CREATE

        connection = self.driver.update_connection(self.context,
                                                   u'123', conn_data)
        self.assertFalse(connection.is_dirty)
        self.assertEqual(u'Tunnel0', connection.tunnel)
        self.assertEqual(constants.PENDING_CREATE, connection.last_status)
        self.assertEqual(1, self.conn_create.call_count)

    def test_detect_no_change_to_ipsec_connection(self):
        """No change to IPSec connection - nop."""
        # Make existing service, and connection that was active
        vpn_service = self.driver.create_vpn_service(self.service123_data)
        connection = vpn_service.create_connection(self.conn1_data)

        self.assertFalse(connection.check_for_changes(self.conn1_data))

    def test_detect_state_only_change_to_ipsec_connection(self):
        """Only IPSec connection state changed - update."""
        # Make existing service, and connection that was active
        vpn_service = self.driver.create_vpn_service(self.service123_data)
        connection = vpn_service.create_connection(self.conn1_data)

        conn_data = copy.deepcopy(self.conn1_data)
        conn_data[u'admin_state_up'] = False
        self.assertFalse(connection.check_for_changes(conn_data))

    def test_detect_non_state_change_to_ipsec_connection(self):
        """Connection change instead of/in addition to state - update."""
        # Make existing service, and connection that was active
        vpn_service = self.driver.create_vpn_service(self.service123_data)
        connection = vpn_service.create_connection(self.conn1_data)

        conn_data = copy.deepcopy(self.conn1_data)
        conn_data[u'ipsec_policy'][u'encryption_algorithm'] = u'aes-256'
        self.assertTrue(connection.check_for_changes(conn_data))

    def test_update_ipsec_connection_changed_admin_down(self):
        """Notified of connection state change - update.

        For a connection that was previously created, expect to
        force connection down on an admin down (only) change.
        """

        # Make existing service, and connection that was active
        vpn_service = self.driver.create_vpn_service(self.service123_data)
        vpn_service.create_connection(self.conn1_data)

        # Simulate that notification of connection update received
        self.driver.mark_existing_connections_as_dirty()
        # Modify the connection data for the 'sync'
        conn_data = copy.deepcopy(self.conn1_data)
        conn_data[u'admin_state_up'] = False

        connection = self.driver.update_connection(self.context,
                                                   '123', conn_data)
        self.assertFalse(connection.is_dirty)
        self.assertEqual(u'Tunnel0', connection.tunnel)
        self.assertEqual(constants.ACTIVE, connection.last_status)
        self.assertFalse(self.conn_create.called)
        self.assertFalse(connection.is_admin_up)
        self.assertTrue(connection.forced_down)
        self.assertEqual(1, self.admin_state.call_count)

    def test_update_ipsec_connection_changed_config(self):
        """Notified of connection changing config - update.

        Goal here is to detect that the connection is deleted and then
        created, but not that the specific values have changed, so picking
        arbitrary value (MTU).
        """
        # Make existing service, and connection that was active
        vpn_service = self.driver.create_vpn_service(self.service123_data)
        vpn_service.create_connection(self.conn1_data)

        # Simulate that notification of connection update received
        self.driver.mark_existing_connections_as_dirty()
        # Modify the connection data for the 'sync'
        conn_data = copy.deepcopy(self.conn1_data)
        conn_data[u'mtu'] = 9200

        connection = self.driver.update_connection(self.context,
                                                   '123', conn_data)
        self.assertFalse(connection.is_dirty)
        self.assertEqual(u'Tunnel0', connection.tunnel)
        self.assertEqual(constants.ACTIVE, connection.last_status)
        self.assertEqual(1, self.conn_create.call_count)
        self.assertEqual(1, self.conn_delete.call_count)
        self.assertTrue(connection.is_admin_up)
        self.assertFalse(connection.forced_down)
        self.assertFalse(self.admin_state.called)

    def test_update_of_unknown_ipsec_connection(self):
        """Notified of update of unknown connection - create.

        Occurs if agent restarts and receives a notification of change
        to connection, but has no previous record of the connection.
        Result will be to rebuild the connection.
        """
        # Will have previously created service, but don't know of connection
        self.driver.create_vpn_service(self.service123_data)

        # Simulate that notification of connection update received
        self.driver.mark_existing_connections_as_dirty()
        conn_data = copy.deepcopy(self.conn1_data)
        conn_data[u'status'] = constants.DOWN

        connection = self.driver.update_connection(self.context,
                                                   u'123', conn_data)
        self.assertFalse(connection.is_dirty)
        self.assertEqual(u'Tunnel0', connection.tunnel)
        self.assertEqual(constants.DOWN, connection.last_status)
        self.assertEqual(1, self.conn_create.call_count)
        self.assertTrue(connection.is_admin_up)
        self.assertFalse(connection.forced_down)
        self.assertFalse(self.admin_state.called)

    def test_update_missing_connection_admin_down(self):
        """Connection not present is in admin down state - nop.

        If the agent has restarted, and a sync notification occurs with
        a connection that is in admin down state, recreate the connection,
        but indicate that the connection is down.
        """
        # Make existing service, but no connection
        self.driver.create_vpn_service(self.service123_data)

        conn_data = copy.deepcopy(self.conn1_data)
        conn_data.update({u'status': constants.DOWN,
                          u'admin_state_up': False})
        connection = self.driver.update_connection(self.context,
                                                   u'123', conn_data)
        self.assertIsNotNone(connection)
        self.assertFalse(connection.is_dirty)
        self.assertEqual(1, self.conn_create.call_count)
        self.assertFalse(connection.is_admin_up)
        self.assertTrue(connection.forced_down)
        self.assertEqual(1, self.admin_state.call_count)

    def test_update_connection_admin_up(self):
        """Connection updated to admin up state - record."""
        # Make existing service, and connection that was admin down
        conn_data = copy.deepcopy(self.conn1_data)
        conn_data.update({u'status': constants.DOWN, u'admin_state_up': False})
        service_data = {u'id': u'123',
                        u'status': constants.DOWN,
                        u'admin_state_up': True,
                        u'ipsec_conns': [conn_data]}
        service_data.update(self.router_info)
        self.driver.update_service(self.context, service_data)

        # Simulate that notification of connection update received
        self.driver.mark_existing_connections_as_dirty()
        # Now simulate that the notification shows the connection admin up
        new_conn_data = copy.deepcopy(conn_data)
        new_conn_data[u'admin_state_up'] = True

        connection = self.driver.update_connection(self.context,
                                                   u'123', new_conn_data)
        self.assertFalse(connection.is_dirty)
        self.assertEqual(u'Tunnel0', connection.tunnel)
        self.assertEqual(constants.DOWN, connection.last_status)
        self.assertTrue(connection.is_admin_up)
        self.assertFalse(connection.forced_down)
        self.assertEqual(2, self.admin_state.call_count)

    def test_update_for_vpn_service_create(self):
        """Creation of new IPSec connection on new VPN service - create.

        Service will be created and marked as 'clean', and update
        processing for connection will occur (create).
        """
        conn_data = copy.deepcopy(self.conn1_data)
        conn_data[u'status'] = constants.PENDING_CREATE
        service_data = {u'id': u'123',
                        u'status': constants.PENDING_CREATE,
                        u'admin_state_up': True,
                        u'ipsec_conns': [conn_data]}
        service_data.update(self.router_info)
        vpn_service = self.driver.update_service(self.context, service_data)
        self.assertFalse(vpn_service.is_dirty)
        self.assertEqual(constants.PENDING_CREATE, vpn_service.last_status)
        connection = vpn_service.get_connection(u'1')
        self.assertIsNotNone(connection)
        self.assertFalse(connection.is_dirty)
        self.assertEqual(u'Tunnel0', connection.tunnel)
        self.assertEqual(constants.PENDING_CREATE, connection.last_status)
        self.assertEqual(1, self.conn_create.call_count)
        self.assertTrue(connection.is_admin_up)
        self.assertFalse(connection.forced_down)
        self.assertFalse(self.admin_state.called)

    def test_update_for_new_connection_on_existing_service(self):
        """Creating a new IPSec connection on an existing service."""
        # Create the service before testing, and mark it dirty
        prev_vpn_service = self.driver.create_vpn_service(self.service123_data)
        self.driver.mark_existing_connections_as_dirty()
        conn_data = copy.deepcopy(self.conn1_data)
        conn_data[u'status'] = constants.PENDING_CREATE
        service_data = {u'id': u'123',
                        u'status': constants.ACTIVE,
                        u'admin_state_up': True,
                        u'ipsec_conns': [conn_data]}
        service_data.update(self.router_info)
        vpn_service = self.driver.update_service(self.context, service_data)
        # Should reuse the entry and update the status
        self.assertEqual(prev_vpn_service, vpn_service)
        self.assertFalse(vpn_service.is_dirty)
        self.assertEqual(constants.ACTIVE, vpn_service.last_status)
        connection = vpn_service.get_connection(u'1')
        self.assertIsNotNone(connection)
        self.assertFalse(connection.is_dirty)
        self.assertEqual(u'Tunnel0', connection.tunnel)
        self.assertEqual(constants.PENDING_CREATE, connection.last_status)
        self.assertEqual(1, self.conn_create.call_count)

    def test_update_for_vpn_service_with_one_unchanged_connection(self):
        """Existing VPN service and IPSec connection without any changes - nop.

        Service and connection will be marked clean. No processing for
        either, as there are no changes.
        """
        # Create a service and add in a connection that is active
        prev_vpn_service = self.driver.create_vpn_service(self.service123_data)
        prev_vpn_service.create_connection(self.conn1_data)

        self.driver.mark_existing_connections_as_dirty()
        # Create notification with conn unchanged and service already created
        service_data = {u'id': u'123',
                        u'status': constants.ACTIVE,
                        u'admin_state_up': True,
                        u'ipsec_conns': [self.conn1_data]}
        service_data.update(self.router_info)
        vpn_service = self.driver.update_service(self.context, service_data)
        # Should reuse the entry and update the status
        self.assertEqual(prev_vpn_service, vpn_service)
        self.assertFalse(vpn_service.is_dirty)
        self.assertEqual(constants.ACTIVE, vpn_service.last_status)
        connection = vpn_service.get_connection(u'1')
        self.assertIsNotNone(connection)
        self.assertFalse(connection.is_dirty)
        self.assertEqual(u'Tunnel0', connection.tunnel)
        self.assertEqual(constants.ACTIVE, connection.last_status)
        self.assertFalse(self.conn_create.called)

    def test_update_service_admin_down(self):
        """VPN service updated to admin down state - force all down.

        If service is down, then all connections are forced down.
        """
        # Create an "existing" service, prior to notification
        prev_vpn_service = self.driver.create_vpn_service(self.service123_data)

        self.driver.mark_existing_connections_as_dirty()
        service_data = {u'id': u'123',
                        u'status': constants.DOWN,
                        u'admin_state_up': False,
                        u'ipsec_conns': [self.conn1_data]}
        service_data.update(self.router_info)
        vpn_service = self.driver.update_service(self.context, service_data)
        self.assertEqual(prev_vpn_service, vpn_service)
        self.assertFalse(vpn_service.is_dirty)
        self.assertFalse(vpn_service.is_admin_up)
        self.assertEqual(constants.DOWN, vpn_service.last_status)
        conn = vpn_service.get_connection(u'1')
        self.assertIsNotNone(conn)
        self.assertFalse(conn.is_dirty)
        self.assertTrue(conn.forced_down)
        self.assertTrue(conn.is_admin_up)

    def test_update_new_service_admin_down(self):
        """Unknown VPN service updated to admin down state - nop.

        Can happen if agent restarts and then gets its first notificaiton
        of a service that is in the admin down state. Structures will be
        created, but forced down.
        """
        service_data = {u'id': u'123',
                        u'status': constants.DOWN,
                        u'admin_state_up': False,
                        u'ipsec_conns': [self.conn1_data]}
        service_data.update(self.router_info)
        vpn_service = self.driver.update_service(self.context, service_data)
        self.assertIsNotNone(vpn_service)
        self.assertFalse(vpn_service.is_dirty)
        self.assertFalse(vpn_service.is_admin_up)
        self.assertEqual(constants.DOWN, vpn_service.last_status)
        conn = vpn_service.get_connection(u'1')
        self.assertIsNotNone(conn)
        self.assertFalse(conn.is_dirty)
        self.assertTrue(conn.forced_down)
        self.assertTrue(conn.is_admin_up)

    def test_update_service_admin_up(self):
        """VPN service updated to admin up state - restore.

        If service is up now, then connections that are admin up will come
        up and connections that are admin down, will remain down.
        """
        # Create an "existing" service, prior to notification
        prev_vpn_service = self.driver.create_vpn_service(self.service123_data)
        self.driver.mark_existing_connections_as_dirty()
        conn_data1 = {u'id': u'1', u'status': constants.DOWN,
                      u'admin_state_up': False,
                      u'cisco': {u'site_conn_id': u'Tunnel0'}}
        conn_data2 = {u'id': u'2', u'status': constants.ACTIVE,
                      u'admin_state_up': True,
                      u'cisco': {u'site_conn_id': u'Tunnel1'}}
        service_data = {u'id': u'123',
                        u'status': constants.DOWN,
                        u'admin_state_up': True,
                        u'ipsec_conns': [conn_data1, conn_data2]}
        service_data.update(self.router_info)
        vpn_service = self.driver.update_service(self.context, service_data)
        self.assertEqual(prev_vpn_service, vpn_service)
        self.assertFalse(vpn_service.is_dirty)
        self.assertTrue(vpn_service.is_admin_up)
        self.assertEqual(constants.DOWN, vpn_service.last_status)
        conn1 = vpn_service.get_connection(u'1')
        self.assertIsNotNone(conn1)
        self.assertFalse(conn1.is_dirty)
        self.assertTrue(conn1.forced_down)
        self.assertFalse(conn1.is_admin_up)
        conn2 = vpn_service.get_connection(u'2')
        self.assertIsNotNone(conn2)
        self.assertFalse(conn2.is_dirty)
        self.assertFalse(conn2.forced_down)
        self.assertTrue(conn2.is_admin_up)

    def test_update_of_unknown_service_create(self):
        """Create of VPN service that is currently unknown - record.

        If agent is restarted or user changes VPN service to admin up, the
        notification may contain a VPN service with an IPSec connection
        that is not in PENDING_CREATE state.
        """
        conn_data = {u'id': u'1', u'status': constants.DOWN,
                     u'admin_state_up': True,
                     u'cisco': {u'site_conn_id': u'Tunnel0'}}
        service_data = {u'id': u'123',
                        u'status': constants.ACTIVE,
                        u'admin_state_up': True,
                        u'ipsec_conns': [conn_data]}
        service_data.update(self.router_info)
        vpn_service = self.driver.update_service(self.context, service_data)
        self.assertFalse(vpn_service.is_dirty)
        self.assertEqual(constants.ACTIVE, vpn_service.last_status)
        connection = vpn_service.get_connection(u'1')
        self.assertIsNotNone(connection)
        self.assertFalse(connection.is_dirty)
        self.assertEqual(u'Tunnel0', connection.tunnel)
        self.assertEqual(constants.DOWN, connection.last_status)
        self.assertEqual(1, self.conn_create.call_count)

    def _check_connection_for_service(self, count, vpn_service):
        """Helper to check the connection information for a service."""
        connection = vpn_service.get_connection(u'%d' % count)
        self.assertIsNotNone(connection, "for connection %d" % count)
        self.assertFalse(connection.is_dirty, "for connection %d" % count)
        self.assertEqual(u'Tunnel%d' % count, connection.tunnel,
                         "for connection %d" % count)
        self.assertEqual(constants.PENDING_CREATE, connection.last_status,
                         "for connection %d" % count)
        return count + 1

    def notification_for_two_services_with_two_conns(self):
        """Helper used by tests to create two services, each with two conns."""
        conn1_data = {u'id': u'1', u'status': constants.PENDING_CREATE,
                      u'admin_state_up': True,
                      u'cisco': {u'site_conn_id': u'Tunnel1'}}
        conn2_data = {u'id': u'2', u'status': constants.PENDING_CREATE,
                      u'admin_state_up': True,
                      u'cisco': {u'site_conn_id': u'Tunnel2'}}
        service1_data = {u'id': u'123',
                         u'status': constants.PENDING_CREATE,
                         u'admin_state_up': True,
                         u'ipsec_conns': [conn1_data, conn2_data]}
        service1_data.update(self.router_info)
        conn3_data = {u'id': u'3', u'status': constants.PENDING_CREATE,
                      u'admin_state_up': True,
                      u'cisco': {u'site_conn_id': u'Tunnel3'}}
        conn4_data = {u'id': u'4', u'status': constants.PENDING_CREATE,
                      u'admin_state_up': True,
                      u'cisco': {u'site_conn_id': u'Tunnel4'}}
        service2_data = {u'id': u'456',
                         u'status': constants.PENDING_CREATE,
                         u'admin_state_up': True,
                         u'ipsec_conns': [conn3_data, conn4_data]}
        service2_data.update(self.router_info)
        return service1_data, service2_data

    def test_create_two_connections_on_two_services(self):
        """High level test of multiple VPN services with connections."""
        # Build notification message
        (service1_data,
         service2_data) = self.notification_for_two_services_with_two_conns()
        # Simulate plugin returning notification, when requested
        self.driver.agent_rpc.get_vpn_services_on_host.return_value = [
            service1_data, service2_data]
        vpn_services = self.driver.update_all_services_and_connections(
            self.context)
        self.assertEqual(2, len(vpn_services))
        count = 1
        for vpn_service in vpn_services:
            self.assertFalse(vpn_service.is_dirty,
                             "for service %s" % vpn_service)
            self.assertEqual(constants.PENDING_CREATE, vpn_service.last_status,
                             "for service %s" % vpn_service)
            count = self._check_connection_for_service(count, vpn_service)
            count = self._check_connection_for_service(count, vpn_service)
        self.assertEqual(4, self.conn_create.call_count)

    def test_sweep_connection_marked_as_clean(self):
        """Sync updated connection - no action."""
        # Create a service and connection
        vpn_service = self.driver.create_vpn_service(self.service123_data)
        connection = vpn_service.create_connection(self.conn1_data)
        self.driver.mark_existing_connections_as_dirty()
        # Simulate that the update phase visted both of them
        vpn_service.is_dirty = False
        connection.is_dirty = False
        self.driver.remove_unknown_connections(self.context)
        vpn_service = self.driver.service_state.get(u'123')
        self.assertIsNotNone(vpn_service)
        self.assertFalse(vpn_service.is_dirty)
        connection = vpn_service.get_connection(u'1')
        self.assertIsNotNone(connection)
        self.assertFalse(connection.is_dirty)

    def test_sweep_connection_dirty(self):
        """Sync did not update connection - delete."""
        # Create a service and connection
        vpn_service = self.driver.create_vpn_service(self.service123_data)
        vpn_service.create_connection(self.conn1_data)
        self.driver.mark_existing_connections_as_dirty()
        # Simulate that the update phase only visited the service
        vpn_service.is_dirty = False
        self.driver.remove_unknown_connections(self.context)
        vpn_service = self.driver.service_state.get(u'123')
        self.assertIsNotNone(vpn_service)
        self.assertFalse(vpn_service.is_dirty)
        connection = vpn_service.get_connection(u'1')
        self.assertIsNone(connection)
        self.assertEqual(1, self.conn_delete.call_count)

    def test_sweep_service_dirty(self):
        """Sync did not update service - delete it and all conns."""
        # Create a service and connection
        vpn_service = self.driver.create_vpn_service(self.service123_data)
        vpn_service.create_connection(self.conn1_data)
        self.driver.mark_existing_connections_as_dirty()
        # Both the service and the connection are still 'dirty'
        self.driver.remove_unknown_connections(self.context)
        self.assertIsNone(self.driver.service_state.get(u'123'))
        self.assertEqual(1, self.conn_delete.call_count)

    def test_sweep_multiple_services(self):
        """One service and conn updated, one service and conn not."""
        # Create two services, each with a connection
        vpn_service1 = self.driver.create_vpn_service(self.service123_data)
        vpn_service1.create_connection(self.conn1_data)
        service456_data = {u'id': u'456',
                           u'status': constants.ACTIVE,
                           u'admin_state_up': False}
        service456_data.update(self.router_info)
        conn2_data = {u'id': u'2', u'status': constants.ACTIVE,
                      u'admin_state_up': True,
                      u'cisco': {u'site_conn_id': u'Tunnel0'}}
        prev_vpn_service2 = self.driver.create_vpn_service(service456_data)
        prev_connection2 = prev_vpn_service2.create_connection(conn2_data)
        self.driver.mark_existing_connections_as_dirty()
        # Simulate that the update phase visited the first service and conn
        prev_vpn_service2.is_dirty = False
        prev_connection2.is_dirty = False
        self.driver.remove_unknown_connections(self.context)
        self.assertIsNone(self.driver.service_state.get(u'123'))
        vpn_service2 = self.driver.service_state.get(u'456')
        self.assertEqual(prev_vpn_service2, vpn_service2)
        self.assertFalse(vpn_service2.is_dirty)
        connection2 = vpn_service2.get_connection(u'2')
        self.assertEqual(prev_connection2, connection2)
        self.assertFalse(connection2.is_dirty)
        self.assertEqual(1, self.conn_delete.call_count)

    def simulate_mark_update_sweep_for_service_with_conn(self, service_state,
                                                         connection_state):
        """Create internal structures for single service with connection.

        Creates a service and corresponding connection. Then, simluates
        the mark/update/sweep operation by marking both the service and
        connection as clean and updating their status. Override the REST
        client created for the service, with a mock, so that all calls
        can be mocked out.
        """
        conn_data = {u'id': u'1', u'status': connection_state,
                     u'admin_state_up': True,
                     u'cisco': {u'site_conn_id': u'Tunnel0'}}
        service_data = {u'id': u'123',
                        u'admin_state_up': True}
        service_data.update(self.router_info)
        # Create a service and connection
        vpn_service = self.driver.create_vpn_service(service_data)
        vpn_service.csr = self.csr  # Mocked REST client
        connection = vpn_service.create_connection(conn_data)
        # Simulate that the update phase visited both of them
        vpn_service.is_dirty = False
        vpn_service.connections_removed = False
        vpn_service.last_status = service_state
        vpn_service.is_admin_up = True
        connection.is_dirty = False
        connection.last_status = connection_state
        connection.is_admin_up = True
        connection.forced_down = False
        return vpn_service

    def test_report_fragment_connection_created(self):
        """Generate report section for a created connection."""
        # Prepare service and connection in PENDING_CREATE state
        vpn_service = self.simulate_mark_update_sweep_for_service_with_conn(
            constants.PENDING_CREATE, constants.PENDING_CREATE)
        # Simulate that CSR has reported the connection is still up
        self.csr.read_tunnel_statuses.return_value = [
            (u'Tunnel0', u'UP-ACTIVE'), ]

        # Get the statuses for connections existing on CSR
        tunnels = vpn_service.get_ipsec_connections_status()
        self.assertEqual({u'Tunnel0': constants.ACTIVE}, tunnels)

        # Check that there is a status for this connection
        connection = vpn_service.get_connection(u'1')
        self.assertIsNotNone(connection)
        current_status = connection.find_current_status_in(tunnels)
        self.assertEqual(constants.ACTIVE, current_status)

        # Create report fragment due to change
        self.assertNotEqual(connection.last_status, current_status)
        report_frag = connection.update_status_and_build_report(current_status)
        self.assertEqual(current_status, connection.last_status)
        expected = {'1': {'status': constants.ACTIVE,
                    'updated_pending_status': True}}
        self.assertEqual(expected, report_frag)

    def test_report_fragment_connection_unchanged_status(self):
        """No report section generated for a created connection."""
        # Prepare service and connection in ACTIVE state
        vpn_service = self.simulate_mark_update_sweep_for_service_with_conn(
            constants.ACTIVE, constants.ACTIVE)
        # Simulate that CSR has reported the connection is up
        self.csr.read_tunnel_statuses.return_value = [
            (u'Tunnel0', u'UP-IDLE'), ]

        # Get the statuses for connections existing on CSR
        tunnels = vpn_service.get_ipsec_connections_status()
        self.assertEqual({u'Tunnel0': constants.ACTIVE}, tunnels)

        # Check that there is a status for this connection
        connection = vpn_service.get_connection(u'1')
        self.assertIsNotNone(connection)
        current_status = connection.find_current_status_in(tunnels)
        self.assertEqual(constants.ACTIVE, current_status)

        # Should be no report, as no change
        self.assertEqual(connection.last_status, current_status)
        report_frag = connection.update_status_and_build_report(current_status)
        self.assertEqual(current_status, connection.last_status)
        self.assertEqual({}, report_frag)

    def test_report_fragment_connection_changed_status(self):
        """Generate report section for connection with changed state."""
        # Prepare service in ACTIVE state and connection in DOWN state
        vpn_service = self.simulate_mark_update_sweep_for_service_with_conn(
            constants.ACTIVE, constants.DOWN)
        # Simulate that CSR has reported the connection is still up
        self.csr.read_tunnel_statuses.return_value = [
            (u'Tunnel0', u'UP-NO-IKE'), ]

        # Get the statuses for connections existing on CSR
        tunnels = vpn_service.get_ipsec_connections_status()
        self.assertEqual({u'Tunnel0': constants.ACTIVE}, tunnels)

        # Check that there is a status for this connection
        connection = vpn_service.get_connection(u'1')
        self.assertIsNotNone(connection)
        current_status = connection.find_current_status_in(tunnels)
        self.assertEqual(constants.ACTIVE, current_status)

        # Create report fragment due to change
        self.assertNotEqual(connection.last_status, current_status)
        report_frag = connection.update_status_and_build_report(current_status)
        self.assertEqual(current_status, connection.last_status)
        expected = {'1': {'status': constants.ACTIVE,
                    'updated_pending_status': False}}
        self.assertEqual(expected, report_frag)

    def test_report_fragment_connection_failed_create(self):
        """Failure test of report fragment for conn that failed creation.

        Normally, without any status from the CSR, the connection report would
        be skipped, but we need to report back failures.
        """
        # Prepare service and connection in PENDING_CREATE state
        vpn_service = self.simulate_mark_update_sweep_for_service_with_conn(
            constants.PENDING_CREATE, constants.PENDING_CREATE)
        # Simulate that CSR does NOT report the status (no tunnel)
        self.csr.read_tunnel_statuses.return_value = []

        # Get the statuses for connections existing on CSR
        tunnels = vpn_service.get_ipsec_connections_status()
        self.assertEqual({}, tunnels)

        # Check that there is a status for this connection
        connection = vpn_service.get_connection(u'1')
        self.assertIsNotNone(connection)
        current_status = connection.find_current_status_in(tunnels)
        self.assertEqual(constants.ERROR, current_status)

        # Create report fragment due to change
        self.assertNotEqual(connection.last_status, current_status)
        report_frag = connection.update_status_and_build_report(current_status)
        self.assertEqual(current_status, connection.last_status)
        expected = {'1': {'status': constants.ERROR,
                    'updated_pending_status': True}}
        self.assertEqual(expected, report_frag)

    def test_report_fragment_connection_admin_down(self):
        """Report for a connection that is in admin down state."""
        # Prepare service and connection with previous status ACTIVE, but
        # with connection admin down
        conn_data = {u'id': u'1', u'status': constants.ACTIVE,
                     u'admin_state_up': False,
                     u'cisco': {u'site_conn_id': u'Tunnel0'}}
        service_data = {u'id': u'123',
                        u'status': constants.ACTIVE,
                        u'admin_state_up': True,
                        u'ipsec_conns': [conn_data]}
        service_data.update(self.router_info)
        vpn_service = self.driver.update_service(self.context, service_data)
        vpn_service.csr = self.csr  # Mocked REST client
        # Tunnel would have been deleted, so simulate no status
        self.csr.read_tunnel_statuses.return_value = []

        connection = vpn_service.get_connection(u'1')
        self.assertIsNotNone(connection)
        self.assertTrue(connection.forced_down)
        self.assertEqual(constants.ACTIVE, connection.last_status)

        # Create report fragment due to change
        report_frag = self.driver.build_report_for_connections_on(vpn_service)
        self.assertEqual(constants.DOWN, connection.last_status)
        expected = {'1': {'status': constants.DOWN,
                    'updated_pending_status': False}}
        self.assertEqual(expected, report_frag)

    def test_report_fragment_two_connections(self):
        """Generate report fragment for two connections on a service."""
        # Prepare service with two connections, one ACTIVE, one DOWN
        conn1_data = {u'id': u'1', u'status': constants.DOWN,
                      u'admin_state_up': True,
                      u'cisco': {u'site_conn_id': u'Tunnel1'}}
        conn2_data = {u'id': u'2', u'status': constants.ACTIVE,
                      u'admin_state_up': True,
                      u'cisco': {u'site_conn_id': u'Tunnel2'}}
        service_data = {u'id': u'123',
                        u'status': constants.ACTIVE,
                        u'admin_state_up': True,
                        u'ipsec_conns': [conn1_data, conn2_data]}
        service_data.update(self.router_info)
        vpn_service = self.driver.update_service(self.context, service_data)
        vpn_service.csr = self.csr  # Mocked REST client
        # Simulate that CSR has reported the connections with diff status
        self.csr.read_tunnel_statuses.return_value = [
            (u'Tunnel1', u'UP-IDLE'), (u'Tunnel2', u'DOWN-NEGOTIATING')]

        # Get the report fragments for the connections
        report_frag = self.driver.build_report_for_connections_on(vpn_service)
        expected = {u'1': {u'status': constants.ACTIVE,
                           u'updated_pending_status': False},
                    u'2': {u'status': constants.DOWN,
                           u'updated_pending_status': False}}
        self.assertEqual(expected, report_frag)

    def test_report_service_create(self):
        """VPN service and IPSec connection created - report."""
        # Simulate creation of the service and connection
        vpn_service = self.simulate_mark_update_sweep_for_service_with_conn(
            constants.PENDING_CREATE, constants.PENDING_CREATE)
        # Simulate that the CSR has created the connection
        self.csr.read_tunnel_statuses.return_value = [
            (u'Tunnel0', u'UP-ACTIVE'), ]

        report = self.driver.build_report_for_service(vpn_service)
        expected_report = {
            u'id': u'123',
            u'updated_pending_status': True,
            u'status': constants.ACTIVE,
            u'ipsec_site_connections': {
                u'1': {u'status': constants.ACTIVE,
                       u'updated_pending_status': True}
            }
        }
        self.assertEqual(expected_report, report)
        # Check that service and connection statuses are updated
        self.assertEqual(constants.ACTIVE, vpn_service.last_status)
        self.assertEqual(constants.ACTIVE,
                         vpn_service.get_connection(u'1').last_status)

    def test_report_service_create_of_first_conn_fails(self):
        """VPN service and IPSec conn created, but conn failed - report.

        Since this is the sole IPSec connection on the service, and the
        create failed (connection in ERROR state), the VPN service's
        status will be set to DOWN.
        """
        # Simulate creation of the service and connection
        vpn_service = self.simulate_mark_update_sweep_for_service_with_conn(
            constants.PENDING_CREATE, constants.PENDING_CREATE)
        # Simulate that the CSR has no info due to failed create
        self.csr.read_tunnel_statuses.return_value = []

        report = self.driver.build_report_for_service(vpn_service)
        expected_report = {
            u'id': u'123',
            u'updated_pending_status': True,
            u'status': constants.DOWN,
            u'ipsec_site_connections': {
                u'1': {u'status': constants.ERROR,
                       u'updated_pending_status': True}
            }
        }
        self.assertEqual(expected_report, report)
        # Check that service and connection statuses are updated
        self.assertEqual(constants.DOWN, vpn_service.last_status)
        self.assertEqual(constants.ERROR,
                         vpn_service.get_connection(u'1').last_status)

    def test_report_connection_created_on_existing_service(self):
        """Creating connection on existing service - report."""
        # Simulate existing service and connection create
        vpn_service = self.simulate_mark_update_sweep_for_service_with_conn(
            constants.ACTIVE, constants.PENDING_CREATE)
        # Simulate that the CSR has created the connection
        self.csr.read_tunnel_statuses.return_value = [
            (u'Tunnel0', u'UP-IDLE'), ]

        report = self.driver.build_report_for_service(vpn_service)
        expected_report = {
            u'id': u'123',
            u'updated_pending_status': False,
            u'status': constants.ACTIVE,
            u'ipsec_site_connections': {
                u'1': {u'status': constants.ACTIVE,
                       u'updated_pending_status': True}
            }
        }
        self.assertEqual(expected_report, report)
        # Check that service and connection statuses are updated
        self.assertEqual(constants.ACTIVE, vpn_service.last_status)
        self.assertEqual(constants.ACTIVE,
                         vpn_service.get_connection(u'1').last_status)

    def test_no_report_no_changes(self):
        """VPN service with unchanged IPSec connection - no report.

        Note: No report will be generated if the last connection on the
        service is deleted. The service (and connection) objects will
        have been removed by the sweep operation and thus not reported.
        On the plugin, the service should be changed to DOWN. Likewise,
        if the service goes to admin down state.
        """
        # Simulate an existing service and connection that are ACTIVE
        vpn_service = self.simulate_mark_update_sweep_for_service_with_conn(
            constants.ACTIVE, constants.ACTIVE)
        # Simulate that the CSR reports the connection still active
        self.csr.read_tunnel_statuses.return_value = [
            (u'Tunnel0', u'UP-ACTIVE'), ]

        report = self.driver.build_report_for_service(vpn_service)
        self.assertEqual({}, report)
        # Check that service and connection statuses are still same
        self.assertEqual(constants.ACTIVE, vpn_service.last_status)
        self.assertEqual(constants.ACTIVE,
                         vpn_service.get_connection(u'1').last_status)

    def test_report_sole_connection_goes_down(self):
        """Only connection on VPN service goes down - report.

        In addition to reporting the status change and recording the new
        state for the IPSec connection, the VPN service status will be
        DOWN.
        """
        # Simulate an existing service and connection that are ACTIVE
        vpn_service = self.simulate_mark_update_sweep_for_service_with_conn(
            constants.ACTIVE, constants.ACTIVE)
        # Simulate that the CSR reports the connection went down
        self.csr.read_tunnel_statuses.return_value = [
            (u'Tunnel0', u'DOWN-NEGOTIATING'), ]

        report = self.driver.build_report_for_service(vpn_service)
        expected_report = {
            u'id': u'123',
            u'updated_pending_status': False,
            u'status': constants.DOWN,
            u'ipsec_site_connections': {
                u'1': {u'status': constants.DOWN,
                       u'updated_pending_status': False}
            }
        }
        self.assertEqual(expected_report, report)
        # Check that service and connection statuses are updated
        self.assertEqual(constants.DOWN, vpn_service.last_status)
        self.assertEqual(constants.DOWN,
                         vpn_service.get_connection(u'1').last_status)

    def test_report_sole_connection_comes_up(self):
        """Only connection on VPN service comes up - report.

        In addition to reporting the status change and recording the new
        state for the IPSec connection, the VPN service status will be
        ACTIVE.
        """
        # Simulate an existing service and connection that are DOWN
        vpn_service = self.simulate_mark_update_sweep_for_service_with_conn(
            constants.DOWN, constants.DOWN)
        # Simulate that the CSR reports the connection came up
        self.csr.read_tunnel_statuses.return_value = [
            (u'Tunnel0', u'UP-NO-IKE'), ]

        report = self.driver.build_report_for_service(vpn_service)
        expected_report = {
            u'id': u'123',
            u'updated_pending_status': False,
            u'status': constants.ACTIVE,
            u'ipsec_site_connections': {
                u'1': {u'status': constants.ACTIVE,
                       u'updated_pending_status': False}
            }
        }
        self.assertEqual(expected_report, report)
        # Check that service and connection statuses are updated
        self.assertEqual(constants.ACTIVE, vpn_service.last_status)
        self.assertEqual(constants.ACTIVE,
                         vpn_service.get_connection(u'1').last_status)

    def test_report_service_with_two_connections_gone_down(self):
        """One service with two connections that went down - report.

        Shows the case where all the connections are down, so that the
        service should report as DOWN, as well.
        """
        # Simulate one service with two ACTIVE connections
        conn1_data = {u'id': u'1', u'status': constants.ACTIVE,
                      u'admin_state_up': True,
                      u'cisco': {u'site_conn_id': u'Tunnel1'}}
        conn2_data = {u'id': u'2', u'status': constants.ACTIVE,
                      u'admin_state_up': True,
                      u'cisco': {u'site_conn_id': u'Tunnel2'}}
        service_data = {u'id': u'123',
                        u'status': constants.ACTIVE,
                        u'admin_state_up': True,
                        u'ipsec_conns': [conn1_data, conn2_data]}
        service_data.update(self.router_info)
        vpn_service = self.driver.update_service(self.context, service_data)
        vpn_service.csr = self.csr  # Mocked REST client
        # Simulate that the CSR has reported that the connections are DOWN
        self.csr.read_tunnel_statuses.return_value = [
            (u'Tunnel1', u'DOWN-NEGOTIATING'), (u'Tunnel2', u'DOWN')]

        report = self.driver.build_report_for_service(vpn_service)
        expected_report = {
            u'id': u'123',
            u'updated_pending_status': False,
            u'status': constants.DOWN,
            u'ipsec_site_connections': {
                u'1': {u'status': constants.DOWN,
                       u'updated_pending_status': False},
                u'2': {u'status': constants.DOWN,
                       u'updated_pending_status': False}}
        }
        self.assertEqual(expected_report, report)
        # Check that service and connection statuses are updated
        self.assertEqual(constants.DOWN, vpn_service.last_status)
        self.assertEqual(constants.DOWN,
                         vpn_service.get_connection(u'1').last_status)
        self.assertEqual(constants.DOWN,
                         vpn_service.get_connection(u'2').last_status)

    def test_report_service_with_connection_removed(self):
        """One service with two connections where one is removed - report.

        With a connection removed and the other connection unchanged,
        normally there would be nothing to report for the connections, but
        we need to report any possible change to the service state. In this
        case, the service was ACTIVE, but since the only ACTIVE connection
        is deleted and the remaining connection is DOWN, the service will
        indicate as DOWN.
        """
        # Simulate one service with one connection up, one down
        conn1_data = {u'id': u'1', u'status': constants.ACTIVE,
                      u'admin_state_up': True,
                      u'mtu': 1500,
                      u'psk': u'secret',
                      u'peer_address': '192.168.1.2',
                      u'peer_cidrs': ['10.1.0.0/24', '10.2.0.0/24'],
                      u'ike_policy': {u'auth_algorithm': u'sha1',
                                      u'encryption_algorithm': u'aes-128',
                                      u'pfs': u'Group5',
                                      u'ike_version': u'v1',
                                      u'lifetime_units': u'seconds',
                                      u'lifetime_value': 3600},
                      u'ipsec_policy': {u'transform_protocol': u'ah',
                                        u'encryption_algorithm': u'aes-128',
                                        u'auth_algorithm': u'sha1',
                                        u'pfs': u'group5',
                                        u'lifetime_units': u'seconds',
                                        u'lifetime_value': 3600},
                      u'cisco': {u'site_conn_id': u'Tunnel1'}}
        conn2_data = {u'id': u'2', u'status': constants.DOWN,
                      u'admin_state_up': True,
                      u'mtu': 1500,
                      u'psk': u'secret',
                      u'peer_address': '192.168.1.2',
                      u'peer_cidrs': ['10.1.0.0/24', '10.2.0.0/24'],
                      u'ike_policy': {u'auth_algorithm': u'sha1',
                                      u'encryption_algorithm': u'aes-128',
                                      u'pfs': u'Group5',
                                      u'ike_version': u'v1',
                                      u'lifetime_units': u'seconds',
                                      u'lifetime_value': 3600},
                      u'ipsec_policy': {u'transform_protocol': u'ah',
                                        u'encryption_algorithm': u'aes-128',
                                        u'auth_algorithm': u'sha1',
                                        u'pfs': u'group5',
                                        u'lifetime_units': u'seconds',
                                        u'lifetime_value': 3600},
                      u'cisco': {u'site_conn_id': u'Tunnel2'}}
        service_data = {u'id': u'123',
                        u'status': constants.ACTIVE,
                        u'admin_state_up': True,
                        u'ipsec_conns': [conn1_data, conn2_data]}
        service_data.update(self.router_info)
        vpn_service = self.driver.update_service(self.context, service_data)
        self.assertEqual(constants.ACTIVE, vpn_service.last_status)
        self.assertEqual(constants.ACTIVE,
                         vpn_service.get_connection(u'1').last_status)
        self.assertEqual(constants.DOWN,
                         vpn_service.get_connection(u'2').last_status)

        # Simulate that one is deleted
        self.driver.mark_existing_connections_as_dirty()
        service_data = {u'id': u'123',
                        u'status': constants.ACTIVE,
                        u'admin_state_up': True,
                        u'ipsec_conns': [conn2_data]}
        service_data.update(self.router_info)
        vpn_service = self.driver.update_service(self.context, service_data)
        vpn_service.csr = self.csr  # Mocked REST client
        self.driver.remove_unknown_connections(self.context)
        self.assertTrue(vpn_service.connections_removed)
        self.assertEqual(constants.ACTIVE, vpn_service.last_status)
        self.assertIsNone(vpn_service.get_connection(u'1'))
        self.assertEqual(constants.DOWN,
                         vpn_service.get_connection(u'2').last_status)

        # Simulate that only one connection reports and status is unchanged,
        # so there will be NO connection info to report.
        self.csr.read_tunnel_statuses.return_value = [(u'Tunnel2', u'DOWN')]
        report = self.driver.build_report_for_service(vpn_service)
        expected_report = {
            u'id': u'123',
            u'updated_pending_status': False,
            u'status': constants.DOWN,
            u'ipsec_site_connections': {}
        }
        self.assertEqual(expected_report, report)
        # Check that service and connection statuses are updated
        self.assertEqual(constants.DOWN, vpn_service.last_status)
        self.assertEqual(constants.DOWN,
                         vpn_service.get_connection(u'2').last_status)

    def test_report_service_admin_down_with_two_connections(self):
        """One service admin down, with two connections - report.

        When the service is admin down, all the connections will report
        as DOWN.
        """
        # Simulate one service (admin down) with two ACTIVE connections
        conn1_data = {u'id': u'1', u'status': constants.ACTIVE,
                      u'admin_state_up': True,
                      u'cisco': {u'site_conn_id': u'Tunnel1'}}
        conn2_data = {u'id': u'2', u'status': constants.ACTIVE,
                      u'admin_state_up': True,
                      u'cisco': {u'site_conn_id': u'Tunnel2'}}
        service_data = {u'id': u'123',
                        u'status': constants.ACTIVE,
                        u'admin_state_up': False,
                        u'ipsec_conns': [conn1_data, conn2_data]}
        service_data.update(self.router_info)
        vpn_service = self.driver.update_service(self.context, service_data)
        vpn_service.csr = self.csr  # Mocked REST client
        # Since service admin down, connections will have been deleted
        self.csr.read_tunnel_statuses.return_value = []

        report = self.driver.build_report_for_service(vpn_service)
        expected_report = {
            u'id': u'123',
            u'updated_pending_status': False,
            u'status': constants.DOWN,
            u'ipsec_site_connections': {
                u'1': {u'status': constants.DOWN,
                       u'updated_pending_status': False},
                u'2': {u'status': constants.DOWN,
                       u'updated_pending_status': False}}
        }
        self.assertEqual(expected_report, report)
        # Check that service and connection statuses are updated
        self.assertEqual(constants.DOWN, vpn_service.last_status)
        self.assertEqual(constants.DOWN,
                         vpn_service.get_connection(u'1').last_status)
        self.assertEqual(constants.DOWN,
                         vpn_service.get_connection(u'2').last_status)

    def test_report_multiple_services(self):
        """Status changes for several services - report."""
        # Simulate creation of the service and connection
        (service1_data,
         service2_data) = self.notification_for_two_services_with_two_conns()
        vpn_service1 = self.driver.update_service(self.context, service1_data)
        vpn_service2 = self.driver.update_service(self.context, service2_data)
        # Simulate that the CSR has created the connections
        vpn_service1.csr = vpn_service2.csr = self.csr  # Mocked REST client
        self.csr.read_tunnel_statuses.return_value = [
            (u'Tunnel1', u'UP-ACTIVE'), (u'Tunnel2', u'DOWN'),
            (u'Tunnel3', u'DOWN-NEGOTIATING'), (u'Tunnel4', u'UP-IDLE')]

        report = self.driver.report_status(self.context)
        expected_report = [{u'id': u'123',
                            u'updated_pending_status': True,
                            u'status': constants.ACTIVE,
                            u'ipsec_site_connections': {
                                u'1': {u'status': constants.ACTIVE,
                                       u'updated_pending_status': True},
                                u'2': {u'status': constants.DOWN,
                                       u'updated_pending_status': True}}
                            },
                           {u'id': u'456',
                            u'updated_pending_status': True,
                            u'status': constants.ACTIVE,
                            u'ipsec_site_connections': {
                                u'3': {u'status': constants.DOWN,
                                       u'updated_pending_status': True},
                                u'4': {u'status': constants.ACTIVE,
                                       u'updated_pending_status': True}}
                            }]
        self.assertEqual(expected_report,
                         sorted(report, key=operator.itemgetter('id')))
        # Check that service and connection statuses are updated
        self.assertEqual(constants.ACTIVE, vpn_service1.last_status)
        self.assertEqual(constants.ACTIVE,
                         vpn_service1.get_connection(u'1').last_status)
        self.assertEqual(constants.DOWN,
                         vpn_service1.get_connection(u'2').last_status)
        self.assertEqual(constants.ACTIVE, vpn_service2.last_status)
        self.assertEqual(constants.DOWN,
                         vpn_service2.get_connection(u'3').last_status)
        self.assertEqual(constants.ACTIVE,
                         vpn_service2.get_connection(u'4').last_status)

    # TODO(pcm) FUTURE - UTs for update action, when supported.

    def test_vpnservice_updated(self):
        with mock.patch.object(self.driver, 'sync') as sync:
            context = mock.Mock()
            self.driver.vpnservice_updated(context)
            sync.assert_called_once_with(context, [])

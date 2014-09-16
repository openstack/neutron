#    (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
#    All Rights Reserved.
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

import mock
from webob import exc

from neutron.extensions import vpnaas
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.tests.unit import test_api_v2
from neutron.tests.unit import test_api_v2_extension


_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path


class VpnaasExtensionTestCase(test_api_v2_extension.ExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        super(VpnaasExtensionTestCase, self).setUp()
        plural_mappings = {'ipsecpolicy': 'ipsecpolicies',
                           'ikepolicy': 'ikepolicies',
                           'ipsec_site_connection': 'ipsec-site-connections'}
        self._setUpExtension(
            'neutron.extensions.vpnaas.VPNPluginBase', constants.VPN,
            vpnaas.RESOURCE_ATTRIBUTE_MAP, vpnaas.Vpnaas,
            'vpn', plural_mappings=plural_mappings,
            use_quota=True)

    def test_ikepolicy_create(self):
        """Test case to create an ikepolicy."""
        ikepolicy_id = _uuid()
        data = {'ikepolicy': {'name': 'ikepolicy1',
                              'description': 'myikepolicy1',
                              'auth_algorithm': 'sha1',
                              'encryption_algorithm': 'aes-128',
                              'phase1_negotiation_mode': 'main',
                              'lifetime': {
                                  'units': 'seconds',
                                  'value': 3600},
                              'ike_version': 'v1',
                              'pfs': 'group5',
                              'tenant_id': _uuid()}}

        return_value = copy.copy(data['ikepolicy'])
        return_value.update({'id': ikepolicy_id})

        instance = self.plugin.return_value
        instance.create_ikepolicy.return_value = return_value
        res = self.api.post(_get_path('vpn/ikepolicies', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_ikepolicy.assert_called_with(mock.ANY,
                                                     ikepolicy=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('ikepolicy', res)
        self.assertEqual(res['ikepolicy'], return_value)

    def test_ikepolicy_list(self):
        """Test case to list all ikepolicies."""
        ikepolicy_id = _uuid()
        return_value = [{'name': 'ikepolicy1',
                         'auth_algorithm': 'sha1',
                         'encryption_algorithm': 'aes-128',
                         'pfs': 'group5',
                         'ike_version': 'v1',
                         'id': ikepolicy_id}]

        instance = self.plugin.return_value
        instance.get_ikepolicies.return_value = return_value

        res = self.api.get(_get_path('vpn/ikepolicies', fmt=self.fmt))

        instance.get_ikepolicies.assert_called_with(mock.ANY,
                                                    fields=mock.ANY,
                                                    filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_ikepolicy_update(self):
        """Test case to update an ikepolicy."""
        ikepolicy_id = _uuid()
        update_data = {'ikepolicy': {'name': 'ikepolicy1',
                                     'encryption_algorithm': 'aes-256'}}
        return_value = {'name': 'ikepolicy1',
                        'auth_algorithm': 'sha1',
                        'encryption_algorithm': 'aes-256',
                        'phase1_negotiation_mode': 'main',
                        'lifetime': {
                            'units': 'seconds',
                            'value': 3600},
                        'ike_version': 'v1',
                        'pfs': 'group5',
                        'tenant_id': _uuid(),
                        'id': ikepolicy_id}

        instance = self.plugin.return_value
        instance.update_ikepolicy.return_value = return_value

        res = self.api.put(_get_path('vpn/ikepolicies', id=ikepolicy_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_ikepolicy.assert_called_with(mock.ANY, ikepolicy_id,
                                                     ikepolicy=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('ikepolicy', res)
        self.assertEqual(res['ikepolicy'], return_value)

    def test_ikepolicy_get(self):
        """Test case to get or show an ikepolicy."""
        ikepolicy_id = _uuid()
        return_value = {'name': 'ikepolicy1',
                        'auth_algorithm': 'sha1',
                        'encryption_algorithm': 'aes-128',
                        'phase1_negotiation_mode': 'main',
                        'lifetime': {
                            'units': 'seconds',
                            'value': 3600},
                        'ike_version': 'v1',
                        'pfs': 'group5',
                        'tenant_id': _uuid(),
                        'id': ikepolicy_id}

        instance = self.plugin.return_value
        instance.get_ikepolicy.return_value = return_value

        res = self.api.get(_get_path('vpn/ikepolicies', id=ikepolicy_id,
                                     fmt=self.fmt))

        instance.get_ikepolicy.assert_called_with(mock.ANY,
                                                  ikepolicy_id,
                                                  fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('ikepolicy', res)
        self.assertEqual(res['ikepolicy'], return_value)

    def test_ikepolicy_delete(self):
        """Test case to delete an ikepolicy."""
        self._test_entity_delete('ikepolicy')

    def test_ipsecpolicy_create(self):
        """Test case to create an ipsecpolicy."""
        ipsecpolicy_id = _uuid()
        data = {'ipsecpolicy': {'name': 'ipsecpolicy1',
                                'description': 'myipsecpolicy1',
                                'auth_algorithm': 'sha1',
                                'encryption_algorithm': 'aes-128',
                                'encapsulation_mode': 'tunnel',
                                'lifetime': {
                                    'units': 'seconds',
                                    'value': 3600},
                                'transform_protocol': 'esp',
                                'pfs': 'group5',
                                'tenant_id': _uuid()}}
        return_value = copy.copy(data['ipsecpolicy'])
        return_value.update({'id': ipsecpolicy_id})

        instance = self.plugin.return_value
        instance.create_ipsecpolicy.return_value = return_value
        res = self.api.post(_get_path('vpn/ipsecpolicies', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_ipsecpolicy.assert_called_with(mock.ANY,
                                                       ipsecpolicy=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('ipsecpolicy', res)
        self.assertEqual(res['ipsecpolicy'], return_value)

    def test_ipsecpolicy_list(self):
        """Test case to list an ipsecpolicy."""
        ipsecpolicy_id = _uuid()
        return_value = [{'name': 'ipsecpolicy1',
                         'auth_algorithm': 'sha1',
                         'encryption_algorithm': 'aes-128',
                         'pfs': 'group5',
                         'id': ipsecpolicy_id}]

        instance = self.plugin.return_value
        instance.get_ipsecpolicies.return_value = return_value

        res = self.api.get(_get_path('vpn/ipsecpolicies', fmt=self.fmt))

        instance.get_ipsecpolicies.assert_called_with(mock.ANY,
                                                      fields=mock.ANY,
                                                      filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_ipsecpolicy_update(self):
        """Test case to update an ipsecpolicy."""
        ipsecpolicy_id = _uuid()
        update_data = {'ipsecpolicy': {'name': 'ipsecpolicy1',
                                       'encryption_algorithm': 'aes-256'}}
        return_value = {'name': 'ipsecpolicy1',
                        'auth_algorithm': 'sha1',
                        'encryption_algorithm': 'aes-128',
                        'encapsulation_mode': 'tunnel',
                        'lifetime': {
                            'units': 'seconds',
                            'value': 3600},
                        'transform_protocol': 'esp',
                        'pfs': 'group5',
                        'tenant_id': _uuid(),
                        'id': ipsecpolicy_id}

        instance = self.plugin.return_value
        instance.update_ipsecpolicy.return_value = return_value

        res = self.api.put(_get_path('vpn/ipsecpolicies',
                                     id=ipsecpolicy_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_ipsecpolicy.assert_called_with(mock.ANY,
                                                       ipsecpolicy_id,
                                                       ipsecpolicy=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('ipsecpolicy', res)
        self.assertEqual(res['ipsecpolicy'], return_value)

    def test_ipsecpolicy_get(self):
        """Test case to get or show an ipsecpolicy."""
        ipsecpolicy_id = _uuid()
        return_value = {'name': 'ipsecpolicy1',
                        'auth_algorithm': 'sha1',
                        'encryption_algorithm': 'aes-128',
                        'encapsulation_mode': 'tunnel',
                        'lifetime': {
                            'units': 'seconds',
                            'value': 3600},
                        'transform_protocol': 'esp',
                        'pfs': 'group5',
                        'tenant_id': _uuid(),
                        'id': ipsecpolicy_id}

        instance = self.plugin.return_value
        instance.get_ipsecpolicy.return_value = return_value

        res = self.api.get(_get_path('vpn/ipsecpolicies',
                                     id=ipsecpolicy_id,
                                     fmt=self.fmt))

        instance.get_ipsecpolicy.assert_called_with(mock.ANY,
                                                    ipsecpolicy_id,
                                                    fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('ipsecpolicy', res)
        self.assertEqual(res['ipsecpolicy'], return_value)

    def test_ipsecpolicy_delete(self):
        """Test case to delete an ipsecpolicy."""
        self._test_entity_delete('ipsecpolicy')

    def test_vpnservice_create(self):
        """Test case to create a vpnservice."""
        vpnservice_id = _uuid()
        data = {'vpnservice': {'name': 'vpnservice1',
                               'description': 'descr_vpn1',
                               'subnet_id': _uuid(),
                               'router_id': _uuid(),
                               'admin_state_up': True,
                               'tenant_id': _uuid()}}
        return_value = copy.copy(data['vpnservice'])
        return_value.update({'status': "ACTIVE", 'id': vpnservice_id})

        instance = self.plugin.return_value
        instance.create_vpnservice.return_value = return_value
        res = self.api.post(_get_path('vpn/vpnservices', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_vpnservice.assert_called_with(mock.ANY,
                                                      vpnservice=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('vpnservice', res)
        self.assertEqual(res['vpnservice'], return_value)

    def test_vpnservice_list(self):
        """Test case to list all vpnservices."""
        vpnservice_id = _uuid()
        return_value = [{'name': 'vpnservice1',
                         'tenant_id': _uuid(),
                         'status': 'ACTIVE',
                         'id': vpnservice_id}]

        instance = self.plugin.return_value
        instance.get_vpnservice.return_value = return_value

        res = self.api.get(_get_path('vpn/vpnservices', fmt=self.fmt))

        instance.get_vpnservices.assert_called_with(mock.ANY,
                                                    fields=mock.ANY,
                                                    filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_vpnservice_update(self):
        """Test case to update a vpnservice."""
        vpnservice_id = _uuid()
        update_data = {'vpnservice': {'admin_state_up': False}}
        return_value = {'name': 'vpnservice1',
                        'admin_state_up': False,
                        'subnet_id': _uuid(),
                        'router_id': _uuid(),
                        'tenant_id': _uuid(),
                        'status': "ACTIVE",
                        'id': vpnservice_id}

        instance = self.plugin.return_value
        instance.update_vpnservice.return_value = return_value

        res = self.api.put(_get_path('vpn/vpnservices',
                                     id=vpnservice_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_vpnservice.assert_called_with(mock.ANY,
                                                      vpnservice_id,
                                                      vpnservice=update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('vpnservice', res)
        self.assertEqual(res['vpnservice'], return_value)

    def test_vpnservice_get(self):
        """Test case to get or show a vpnservice."""
        vpnservice_id = _uuid()
        return_value = {'name': 'vpnservice1',
                        'admin_state_up': True,
                        'subnet_id': _uuid(),
                        'router_id': _uuid(),
                        'tenant_id': _uuid(),
                        'status': "ACTIVE",
                        'id': vpnservice_id}

        instance = self.plugin.return_value
        instance.get_vpnservice.return_value = return_value

        res = self.api.get(_get_path('vpn/vpnservices',
                                     id=vpnservice_id,
                                     fmt=self.fmt))

        instance.get_vpnservice.assert_called_with(mock.ANY,
                                                   vpnservice_id,
                                                   fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('vpnservice', res)
        self.assertEqual(res['vpnservice'], return_value)

    def test_vpnservice_delete(self):
        """Test case to delete a vpnservice."""
        self._test_entity_delete('vpnservice')

    def test_ipsec_site_connection_create(self):
        """Test case to create a ipsec_site_connection."""
        ipsecsite_con_id = _uuid()
        ikepolicy_id = _uuid()
        ipsecpolicy_id = _uuid()
        data = {
            'ipsec_site_connection': {'name': 'connection1',
                                      'description': 'Remote-connection1',
                                      'peer_address': '192.168.1.10',
                                      'peer_id': '192.168.1.10',
                                      'peer_cidrs': ['192.168.2.0/24',
                                                     '192.168.3.0/24'],
                                      'mtu': 1500,
                                      'psk': 'abcd',
                                      'initiator': 'bi-directional',
                                      'dpd': {
                                          'action': 'hold',
                                          'interval': 30,
                                          'timeout': 120},
                                      'ikepolicy_id': ikepolicy_id,
                                      'ipsecpolicy_id': ipsecpolicy_id,
                                      'vpnservice_id': _uuid(),
                                      'admin_state_up': True,
                                      'tenant_id': _uuid()}
        }
        return_value = copy.copy(data['ipsec_site_connection'])
        return_value.update({'status': "ACTIVE", 'id': ipsecsite_con_id})

        instance = self.plugin.return_value
        instance.create_ipsec_site_connection.return_value = return_value
        res = self.api.post(_get_path('vpn/ipsec-site-connections',
                                      fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_ipsec_site_connection.assert_called_with(
            mock.ANY, ipsec_site_connection=data
        )
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('ipsec_site_connection', res)
        self.assertEqual(res['ipsec_site_connection'], return_value)

    def test_ipsec_site_connection_list(self):
        """Test case to list all ipsec_site_connections."""
        ipsecsite_con_id = _uuid()
        return_value = [{'name': 'connection1',
                         'peer_address': '192.168.1.10',
                         'peer_cidrs': ['192.168.2.0/24', '192.168.3.0/24'],
                         'route_mode': 'static',
                         'auth_mode': 'psk',
                         'tenant_id': _uuid(),
                         'status': 'ACTIVE',
                         'id': ipsecsite_con_id}]

        instance = self.plugin.return_value
        instance.get_ipsec_site_connections.return_value = return_value

        res = self.api.get(
            _get_path('vpn/ipsec-site-connections', fmt=self.fmt))

        instance.get_ipsec_site_connections.assert_called_with(
            mock.ANY, fields=mock.ANY, filters=mock.ANY
        )
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_ipsec_site_connection_update(self):
        """Test case to update a ipsec_site_connection."""
        ipsecsite_con_id = _uuid()
        update_data = {'ipsec_site_connection': {'admin_state_up': False}}
        return_value = {'name': 'connection1',
                        'description': 'Remote-connection1',
                        'peer_address': '192.168.1.10',
                        'peer_id': '192.168.1.10',
                        'peer_cidrs': ['192.168.2.0/24', '192.168.3.0/24'],
                        'mtu': 1500,
                        'psk': 'abcd',
                        'initiator': 'bi-directional',
                        'dpd': {
                            'action': 'hold',
                            'interval': 30,
                            'timeout': 120},
                        'ikepolicy_id': _uuid(),
                        'ipsecpolicy_id': _uuid(),
                        'vpnservice_id': _uuid(),
                        'admin_state_up': False,
                        'tenant_id': _uuid(),
                        'status': 'ACTIVE',
                        'id': ipsecsite_con_id}

        instance = self.plugin.return_value
        instance.update_ipsec_site_connection.return_value = return_value

        res = self.api.put(_get_path('vpn/ipsec-site-connections',
                                     id=ipsecsite_con_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_ipsec_site_connection.assert_called_with(
            mock.ANY, ipsecsite_con_id, ipsec_site_connection=update_data
        )

        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('ipsec_site_connection', res)
        self.assertEqual(res['ipsec_site_connection'], return_value)

    def test_ipsec_site_connection_get(self):
        """Test case to get or show a ipsec_site_connection."""
        ipsecsite_con_id = _uuid()
        return_value = {'name': 'connection1',
                        'description': 'Remote-connection1',
                        'peer_address': '192.168.1.10',
                        'peer_id': '192.168.1.10',
                        'peer_cidrs': ['192.168.2.0/24',
                                       '192.168.3.0/24'],
                        'mtu': 1500,
                        'psk': 'abcd',
                        'initiator': 'bi-directional',
                        'dpd': {
                            'action': 'hold',
                            'interval': 30,
                            'timeout': 120},
                        'ikepolicy_id': _uuid(),
                        'ipsecpolicy_id': _uuid(),
                        'vpnservice_id': _uuid(),
                        'admin_state_up': True,
                        'tenant_id': _uuid(),
                        'status': 'ACTIVE',
                        'id': ipsecsite_con_id}

        instance = self.plugin.return_value
        instance.get_ipsec_site_connection.return_value = return_value

        res = self.api.get(_get_path('vpn/ipsec-site-connections',
                                     id=ipsecsite_con_id,
                                     fmt=self.fmt))

        instance.get_ipsec_site_connection.assert_called_with(
            mock.ANY, ipsecsite_con_id, fields=mock.ANY
        )
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('ipsec_site_connection', res)
        self.assertEqual(res['ipsec_site_connection'], return_value)

    def test_ipsec_site_connection_delete(self):
        """Test case to delete a ipsec_site_connection."""
        self._test_entity_delete('ipsec_site_connection')


class VpnaasExtensionTestCaseXML(VpnaasExtensionTestCase):
    fmt = 'xml'

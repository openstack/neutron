# Copyright 2014 VMware, Inc
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

import contextlib
import copy

import webob.exc

from neutron.api.v2 import attributes
from neutron.db.vpn import vpn_db
from neutron.extensions import vpnaas
from neutron import manager
from neutron.openstack.common import uuidutils
from neutron.tests.unit.db.vpn import test_db_vpnaas
from neutron.tests.unit.vmware.vshield import test_edge_router

_uuid = uuidutils.generate_uuid


class VPNTestExtensionManager(
        test_edge_router.ServiceRouterTestExtensionManager):

    def get_resources(self):
        # If l3 resources have been loaded and updated by main API
        # router, update the map in the l3 extension so it will load
        # the same attributes as the API router
        resources = super(VPNTestExtensionManager, self).get_resources()
        vpn_attr_map = copy.deepcopy(vpnaas.RESOURCE_ATTRIBUTE_MAP)
        for res in vpnaas.RESOURCE_ATTRIBUTE_MAP.keys():
            attr_info = attributes.RESOURCE_ATTRIBUTE_MAP.get(res)
            if attr_info:
                vpnaas.RESOURCE_ATTRIBUTE_MAP[res] = attr_info
        vpn_resources = vpnaas.Vpnaas.get_resources()
        # restore the original resources once the controllers are created
        vpnaas.RESOURCE_ATTRIBUTE_MAP = vpn_attr_map
        resources.extend(vpn_resources)
        return resources


class TestVpnPlugin(test_db_vpnaas.VPNTestMixin,
                    test_edge_router.ServiceRouterTest):

    def vcns_vpn_patch(self):
        instance = self.vcns_instance
        instance.return_value.update_ipsec_config.side_effect = (
            self.fc2.update_ipsec_config)
        instance.return_value.get_ipsec_config.side_effect = (
            self.fc2.get_ipsec_config)
        instance.return_value.delete_ipsec_config.side_effect = (
            self.fc2.delete_ipsec_config)

    def setUp(self):
        # Save the global RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for resource, attrs in attributes.RESOURCE_ATTRIBUTE_MAP.items():
            self.saved_attr_map[resource] = attrs.copy()

        super(TestVpnPlugin, self).setUp(ext_mgr=VPNTestExtensionManager())
        self.vcns_vpn_patch()
        self.plugin = manager.NeutronManager.get_plugin()
        self.router_id = None

    def tearDown(self):
        super(TestVpnPlugin, self).tearDown()
        # Restore the global RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map
        self.ext_api = None
        self.plugin = None

    @contextlib.contextmanager
    def router(self, vlan_id=None):
        with self._create_l3_ext_network(vlan_id) as net:
            with self.subnet(cidr='100.0.0.0/24', network=net) as s:
                data = {'router': {'tenant_id': self._tenant_id}}
                data['router']['service_router'] = True
                router_req = self.new_create_request('routers', data, self.fmt)

                res = router_req.get_response(self.ext_api)
                router = self.deserialize(self.fmt, res)
                self._add_external_gateway_to_router(
                    router['router']['id'],
                    s['subnet']['network_id'])
                router = self._show('routers', router['router']['id'])
                yield router

                self._delete('routers', router['router']['id'])

    def test_create_vpnservice(self, **extras):
        """Test case to create a vpnservice."""
        description = 'my-vpn-service'
        expected = {'name': 'vpnservice1',
                    'description': 'my-vpn-service',
                    'admin_state_up': True,
                    'status': 'ACTIVE',
                    'tenant_id': self._tenant_id, }

        expected.update(extras)
        with self.subnet(cidr='10.2.0.0/24') as subnet:
            with self.router() as router:
                expected['router_id'] = router['router']['id']
                expected['subnet_id'] = subnet['subnet']['id']
                name = expected['name']
                with self.vpnservice(name=name,
                                     subnet=subnet,
                                     router=router,
                                     description=description,
                                     **extras) as vpnservice:
                    self.assertEqual(dict((k, v) for k, v in
                                          vpnservice['vpnservice'].items()
                                          if k in expected),
                                     expected)

    def test_create_vpnservices_with_same_router(self, **extras):
        """Test case to create two vpnservices with same router."""
        with self.subnet(cidr='10.2.0.0/24') as subnet:
            with self.router() as router:
                with self.vpnservice(name='vpnservice1',
                                     subnet=subnet,
                                     router=router):
                    res = self._create_vpnservice(
                        'json', 'vpnservice2', True,
                        router_id=(router['router']['id']),
                        subnet_id=(subnet['subnet']['id']))
                    self.assertEqual(
                        res.status_int, webob.exc.HTTPConflict.code)

    def test_update_vpnservice(self):
        """Test case to update a vpnservice."""
        name = 'new_vpnservice1'
        expected = [('name', name)]
        with contextlib.nested(
            self.subnet(cidr='10.2.0.0/24'),
            self.router()) as (subnet, router):
            with self.vpnservice(name=name,
                                 subnet=subnet,
                                 router=router) as vpnservice:
                expected.append(('subnet_id',
                                 vpnservice['vpnservice']['subnet_id']))
                expected.append(('router_id',
                                 vpnservice['vpnservice']['router_id']))
                data = {'vpnservice': {'name': name,
                                       'admin_state_up': False}}
                expected.append(('admin_state_up', False))
                self._set_active(vpn_db.VPNService,
                                 vpnservice['vpnservice']['id'])
                req = self.new_update_request(
                    'vpnservices',
                    data,
                    vpnservice['vpnservice']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in expected:
                    self.assertEqual(res['vpnservice'][k], v)

    def test_delete_vpnservice(self):
        """Test case to delete a vpnservice."""
        with self.subnet(cidr='10.2.0.0/24') as subnet:
            with self.router() as router:
                with self.vpnservice(name='vpnservice',
                                     subnet=subnet,
                                     router=router,
                                     do_delete=False) as vpnservice:
                    req = self.new_delete_request(
                        'vpnservices', vpnservice['vpnservice']['id'])
                    res = req.get_response(self.ext_api)
                    self.assertEqual(res.status_int, 204)

    def test_delete_router_in_use_by_vpnservice(self):
        """Test delete router in use by vpn service."""
        with self.subnet(cidr='10.2.0.0/24') as subnet:
            with self.router() as router:
                with self.vpnservice(subnet=subnet,
                                     router=router):
                    self._delete('routers', router['router']['id'],
                                 expected_code=webob.exc.HTTPConflict.code)

    def _test_create_ipsec_site_connection(self, key_overrides=None,
                                           ike_key_overrides=None,
                                           ipsec_key_overrides=None,
                                           setup_overrides=None,
                                           expected_status_int=200):
        """Create ipsec_site_connection and check results."""
        params = {'ikename': 'ikepolicy1',
                  'ipsecname': 'ipsecpolicy1',
                  'vpnsname': 'vpnservice1',
                  'subnet_cidr': '10.2.0.0/24',
                  'subnet_version': 4}
        if setup_overrides:
            params.update(setup_overrides)
        expected = {'name': 'connection1',
                    'description': 'my-ipsec-connection',
                    'peer_address': '192.168.1.10',
                    'peer_id': '192.168.1.10',
                    'peer_cidrs': ['192.168.2.0/24', '192.168.3.0/24'],
                    'initiator': 'bi-directional',
                    'mtu': 1500,
                    'tenant_id': self._tenant_id,
                    'psk': 'abcd',
                    'status': 'ACTIVE',
                    'admin_state_up': True}
        if key_overrides:
            expected.update(key_overrides)

        ike_expected = {'name': params['ikename'],
                        'auth_algorithm': 'sha1',
                        'encryption_algorithm': 'aes-128',
                        'ike_version': 'v1',
                        'pfs': 'group5'}
        if ike_key_overrides:
            ike_expected.update(ike_key_overrides)

        ipsec_expected = {'name': params['ipsecname'],
                          'auth_algorithm': 'sha1',
                          'encryption_algorithm': 'aes-128',
                          'pfs': 'group5'}
        if ipsec_key_overrides:
            ipsec_expected.update(ipsec_key_overrides)

        dpd = {'action': 'hold',
               'interval': 40,
               'timeout': 120}
        with contextlib.nested(
            self.ikepolicy(self.fmt, ike_expected['name'],
                           ike_expected['auth_algorithm'],
                           ike_expected['encryption_algorithm'],
                           ike_version=ike_expected['ike_version'],
                           pfs=ike_expected['pfs']),
            self.ipsecpolicy(self.fmt, ipsec_expected['name'],
                             ipsec_expected['auth_algorithm'],
                             ipsec_expected['encryption_algorithm'],
                             pfs=ipsec_expected['pfs']),
            self.subnet(cidr=params['subnet_cidr'],
                        ip_version=params['subnet_version']),
            self.router()) as (
                ikepolicy, ipsecpolicy, subnet, router):
                with self.vpnservice(name=params['vpnsname'], subnet=subnet,
                                     router=router) as vpnservice1:
                    expected['ikepolicy_id'] = ikepolicy['ikepolicy']['id']
                    expected['ipsecpolicy_id'] = (
                        ipsecpolicy['ipsecpolicy']['id']
                    )
                    expected['vpnservice_id'] = (
                        vpnservice1['vpnservice']['id']
                    )
                    try:
                        with self.ipsec_site_connection(
                                self.fmt,
                                expected['name'],
                                expected['peer_address'],
                                expected['peer_id'],
                                expected['peer_cidrs'],
                                expected['mtu'],
                                expected['psk'],
                                expected['initiator'],
                                dpd['action'],
                                dpd['interval'],
                                dpd['timeout'],
                                vpnservice1,
                                ikepolicy,
                                ipsecpolicy,
                                expected['admin_state_up'],
                                description=expected['description']
                        ) as ipsec_site_connection:
                            if expected_status_int != 200:
                                self.fail("Expected failure on create")
                            self._check_ipsec_site_connection(
                                ipsec_site_connection['ipsec_site_connection'],
                                expected,
                                dpd)
                    except webob.exc.HTTPClientError as ce:
                        self.assertEqual(ce.code, expected_status_int)

    def test_create_ipsec_site_connection(self, **extras):
        """Test case to create an ipsec_site_connection."""
        self._test_create_ipsec_site_connection(key_overrides=extras)

    def test_create_ipsec_site_connection_invalid_ikepolicy(self):
        self._test_create_ipsec_site_connection(
            ike_key_overrides={'ike_version': 'v2'},
            expected_status_int=400)

    def test_create_ipsec_site_connection_invalid_ipsecpolicy(self):
        self._test_create_ipsec_site_connection(
            ipsec_key_overrides={'encryption_algorithm': 'aes-192'},
            expected_status_int=400)
        self._test_create_ipsec_site_connection(
            ipsec_key_overrides={'pfs': 'group14'},
            expected_status_int=400)

    def _test_update_ipsec_site_connection(self,
                                           update={'name': 'new name'},
                                           overrides=None,
                                           expected_status_int=200):
        """Creates and then updates ipsec_site_connection."""
        expected = {'name': 'new_ipsec_site_connection',
                    'ikename': 'ikepolicy1',
                    'ipsecname': 'ipsecpolicy1',
                    'vpnsname': 'vpnservice1',
                    'description': 'my-ipsec-connection',
                    'peer_address': '192.168.1.10',
                    'peer_id': '192.168.1.10',
                    'peer_cidrs': ['192.168.2.0/24', '192.168.3.0/24'],
                    'initiator': 'bi-directional',
                    'mtu': 1500,
                    'tenant_id': self._tenant_id,
                    'psk': 'abcd',
                    'status': 'ACTIVE',
                    'admin_state_up': True,
                    'action': 'hold',
                    'interval': 40,
                    'timeout': 120,
                    'subnet_cidr': '10.2.0.0/24',
                    'subnet_version': 4,
                    'make_active': True}
        if overrides:
            expected.update(overrides)

        with contextlib.nested(
                self.ikepolicy(name=expected['ikename']),
                self.ipsecpolicy(name=expected['ipsecname']),
                self.subnet(cidr=expected['subnet_cidr'],
                            ip_version=expected['subnet_version']),
                self.router()
        ) as (ikepolicy, ipsecpolicy, subnet, router):
            with self.vpnservice(name=expected['vpnsname'], subnet=subnet,
                                 router=router) as vpnservice1:
                expected['vpnservice_id'] = vpnservice1['vpnservice']['id']
                expected['ikepolicy_id'] = ikepolicy['ikepolicy']['id']
                expected['ipsecpolicy_id'] = ipsecpolicy['ipsecpolicy']['id']
                with self.ipsec_site_connection(
                    self.fmt,
                    expected['name'],
                    expected['peer_address'],
                    expected['peer_id'],
                    expected['peer_cidrs'],
                    expected['mtu'],
                    expected['psk'],
                    expected['initiator'],
                    expected['action'],
                    expected['interval'],
                    expected['timeout'],
                    vpnservice1,
                    ikepolicy,
                    ipsecpolicy,
                    expected['admin_state_up'],
                    description=expected['description']
                ) as ipsec_site_connection:
                    data = {'ipsec_site_connection': update}
                    if expected.get('make_active'):
                        self._set_active(
                            vpn_db.IPsecSiteConnection,
                            (ipsec_site_connection['ipsec_site_connection']
                             ['id']))
                    req = self.new_update_request(
                        'ipsec-site-connections',
                        data,
                        ipsec_site_connection['ipsec_site_connection']['id'])
                    res = req.get_response(self.ext_api)
                    self.assertEqual(expected_status_int, res.status_int)
                    if expected_status_int == 200:
                        res_dict = self.deserialize(self.fmt, res)
                        for k, v in update.items():
                            self.assertEqual(
                                res_dict['ipsec_site_connection'][k], v)

    def test_update_ipsec_site_connection(self):
        """Test case for valid updates to IPSec site connection."""
        dpd = {'action': 'hold',
               'interval': 40,
               'timeout': 120}
        self._test_update_ipsec_site_connection(update={'dpd': dpd})
        self._test_update_ipsec_site_connection(update={'mtu': 2000})

    def test_delete_ipsec_site_connection(self):
        """Test case to delete a ipsec_site_connection."""
        with self.ipsec_site_connection(
                do_delete=False) as ipsec_site_connection:
            req = self.new_delete_request(
                'ipsec-site-connections',
                ipsec_site_connection['ipsec_site_connection']['id']
            )
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 204)

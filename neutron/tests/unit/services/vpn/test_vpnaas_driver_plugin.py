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
import contextlib

import mock

from neutron.common import constants
from neutron import context
from neutron.db.vpn import vpn_validator
from neutron import manager
from neutron.plugins.common import constants as p_constants
from neutron.services.vpn.service_drivers import ipsec as ipsec_driver
from neutron.tests.unit.db.vpn import test_db_vpnaas
from neutron.tests.unit.openvswitch import test_agent_scheduler
from neutron.tests.unit import test_agent_ext_plugin

FAKE_HOST = test_agent_ext_plugin.L3_HOSTA
VPN_DRIVER_CLASS = 'neutron.services.vpn.plugin.VPNDriverPlugin'


class TestVPNDriverPlugin(test_db_vpnaas.TestVpnaas,
                          test_agent_scheduler.AgentSchedulerTestMixIn,
                          test_agent_ext_plugin.AgentDBTestMixIn):

    def setUp(self):
        self.adminContext = context.get_admin_context()
        driver_cls_p = mock.patch(
            'neutron.services.vpn.'
            'service_drivers.ipsec.IPsecVPNDriver')
        driver_cls = driver_cls_p.start()
        self.driver = mock.Mock()
        self.driver.service_type = ipsec_driver.IPSEC
        self.driver.validator = vpn_validator.VpnReferenceValidator()
        driver_cls.return_value = self.driver
        super(TestVPNDriverPlugin, self).setUp(
            vpnaas_plugin=VPN_DRIVER_CLASS)

    def test_create_ipsec_site_connection(self, **extras):
        super(TestVPNDriverPlugin, self).test_create_ipsec_site_connection()
        self.driver.create_ipsec_site_connection.assert_called_once_with(
            mock.ANY, mock.ANY)
        self.driver.delete_ipsec_site_connection.assert_called_once_with(
            mock.ANY, mock.ANY)

    def test_delete_vpnservice(self, **extras):
        super(TestVPNDriverPlugin, self).test_delete_vpnservice()
        self.driver.delete_vpnservice.assert_called_once_with(
            mock.ANY, mock.ANY)

    def test_update_vpnservice(self, **extras):
        super(TestVPNDriverPlugin, self).test_update_vpnservice()
        self.driver.update_vpnservice.assert_called_once_with(
            mock.ANY, mock.ANY, mock.ANY)

    @contextlib.contextmanager
    def vpnservice_set(self):
        """Test case to create a ipsec_site_connection."""
        vpnservice_name = "vpn1"
        ipsec_site_connection_name = "ipsec_site_connection"
        ikename = "ikepolicy1"
        ipsecname = "ipsecpolicy1"
        description = "my-vpn-connection"
        keys = {'name': vpnservice_name,
                'description': "my-vpn-connection",
                'peer_address': '192.168.1.10',
                'peer_id': '192.168.1.10',
                'peer_cidrs': ['192.168.2.0/24', '192.168.3.0/24'],
                'initiator': 'bi-directional',
                'mtu': 1500,
                'dpd_action': 'hold',
                'dpd_interval': 40,
                'dpd_timeout': 120,
                'tenant_id': self._tenant_id,
                'psk': 'abcd',
                'status': 'PENDING_CREATE',
                'admin_state_up': True}
        with self.ikepolicy(name=ikename) as ikepolicy:
            with self.ipsecpolicy(name=ipsecname) as ipsecpolicy:
                with self.subnet() as subnet:
                    with self.router() as router:
                        plugin = manager.NeutronManager.get_plugin()
                        agent = {'host': FAKE_HOST,
                                 'agent_type': constants.AGENT_TYPE_L3,
                                 'binary': 'fake-binary',
                                 'topic': 'fake-topic'}
                        plugin.create_or_update_agent(self.adminContext, agent)
                        plugin.schedule_router(
                            self.adminContext, router['router']['id'])
                        with self.vpnservice(name=vpnservice_name,
                                             subnet=subnet,
                                             router=router) as vpnservice1:
                            keys['ikepolicy_id'] = ikepolicy['ikepolicy']['id']
                            keys['ipsecpolicy_id'] = (
                                ipsecpolicy['ipsecpolicy']['id']
                            )
                            keys['vpnservice_id'] = (
                                vpnservice1['vpnservice']['id']
                            )
                            with self.ipsec_site_connection(
                                self.fmt,
                                ipsec_site_connection_name,
                                keys['peer_address'],
                                keys['peer_id'],
                                keys['peer_cidrs'],
                                keys['mtu'],
                                keys['psk'],
                                keys['initiator'],
                                keys['dpd_action'],
                                keys['dpd_interval'],
                                keys['dpd_timeout'],
                                vpnservice1,
                                ikepolicy,
                                ipsecpolicy,
                                keys['admin_state_up'],
                                description=description,
                            ):
                                yield vpnservice1['vpnservice']

    def test_get_agent_hosting_vpn_services(self):
        with self.vpnservice_set():
            service_plugin = manager.NeutronManager.get_service_plugins()[
                p_constants.VPN]
            vpnservices = service_plugin._get_agent_hosting_vpn_services(
                self.adminContext, FAKE_HOST)
            vpnservices = vpnservices.all()
            self.assertEqual(1, len(vpnservices))
            vpnservice_db = vpnservices[0]
            self.assertEqual(1, len(vpnservice_db.ipsec_site_connections))
            ipsec_site_connection = vpnservice_db.ipsec_site_connections[0]
            self.assertIsNotNone(
                ipsec_site_connection['ikepolicy'])
            self.assertIsNotNone(
                ipsec_site_connection['ipsecpolicy'])

    def test_update_status(self):
        with self.vpnservice_set() as vpnservice:
            self._register_agent_states()
            service_plugin = manager.NeutronManager.get_service_plugins()[
                p_constants.VPN]
            service_plugin.update_status_by_agent(
                self.adminContext,
                [{'status': 'ACTIVE',
                  'ipsec_site_connections': {},
                  'updated_pending_status': True,
                  'id': vpnservice['id']}])
            vpnservices = service_plugin._get_agent_hosting_vpn_services(
                self.adminContext, FAKE_HOST)
            vpnservice_db = vpnservices[0]
            self.assertEqual(p_constants.ACTIVE, vpnservice_db['status'])

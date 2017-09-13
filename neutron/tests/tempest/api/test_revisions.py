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

import netaddr

from tempest.common import utils
from tempest.lib import decorators
from tempest.lib import exceptions

from neutron.tests.tempest.api import base
from neutron.tests.tempest.api import base_security_groups as bsg
from neutron.tests.tempest import config


class TestRevisions(base.BaseAdminNetworkTest, bsg.BaseSecGroupTest):

    required_extensions = ['standard-attr-revisions']

    @decorators.idempotent_id('4a26a4be-9c53-483c-bc50-b53f1db10ac6')
    def test_update_network_bumps_revision(self):
        net = self.create_network()
        self.addCleanup(self.client.delete_network, net['id'])
        self.assertIn('revision_number', net)
        updated = self.client.update_network(net['id'], name='newnet')
        self.assertGreater(updated['network']['revision_number'],
                           net['revision_number'])

    @decorators.idempotent_id('4a26a4be-9c53-483c-bc50-b11111113333')
    def test_update_network_constrained_by_revision(self):
        net = self.create_network()
        current = net['revision_number']
        stale = current - 1
        # using a stale number should fail
        self.assertRaises(
            exceptions.PreconditionFailed,
            self.client.update_network,
            net['id'], name='newnet',
            headers={'If-Match': 'revision_number=%s' % stale}
        )

        # using current should pass. in case something is updating the network
        # on the server at the same time, we have to re-read and update to be
        # safe
        for i in range(100):
            current = (self.client.show_network(net['id'])
                       ['network']['revision_number'])
            try:
                self.client.update_network(
                    net['id'], name='newnet',
                    headers={'If-Match': 'revision_number=%s' % current})
            except exceptions.UnexpectedResponseCode:
                continue
            break
        else:
            self.fail("Failed to update network after 100 tries.")

    @decorators.idempotent_id('cac7ecde-12d5-4331-9a03-420899dea077')
    def test_update_port_bumps_revision(self):
        net = self.create_network()
        self.addCleanup(self.client.delete_network, net['id'])
        port = self.create_port(net)
        self.addCleanup(self.client.delete_port, port['id'])
        self.assertIn('revision_number', port)
        updated = self.client.update_port(port['id'], name='newport')
        self.assertGreater(updated['port']['revision_number'],
                           port['revision_number'])

    @decorators.idempotent_id('c1c4fa41-8e89-44d0-9bfc-409f3b66dc57')
    def test_update_subnet_bumps_revision(self):
        net = self.create_network()
        self.addCleanup(self.client.delete_network, net['id'])
        subnet = self.create_subnet(net)
        self.addCleanup(self.client.delete_subnet, subnet['id'])
        self.assertIn('revision_number', subnet)
        updated = self.client.update_subnet(subnet['id'], name='newsub')
        self.assertGreater(updated['subnet']['revision_number'],
                           subnet['revision_number'])

    @decorators.idempotent_id('e8c5d7db-2b8d-4615-a476-6e537437c4f2')
    def test_update_subnetpool_bumps_revision(self):
        sp = self.create_subnetpool('subnetpool', default_prefixlen=24,
                                    prefixes=['10.0.0.0/8'])
        self.addCleanup(self.client.delete_subnetpool, sp['id'])
        self.assertIn('revision_number', sp)
        updated = self.admin_client.update_subnetpool(sp['id'], name='sp2')
        self.assertGreater(updated['subnetpool']['revision_number'],
                           sp['revision_number'])

    @decorators.idempotent_id('e8c5d7db-2b8d-4567-a326-6e123437c4d1')
    def test_update_subnet_bumps_network_revision(self):
        net = self.create_network()
        self.addCleanup(self.client.delete_network, net['id'])
        subnet = self.create_subnet(net)
        updated = self.client.show_network(net['id'])
        self.assertGreater(updated['network']['revision_number'],
                           net['revision_number'])
        self.client.delete_subnet(subnet['id'])
        updated2 = self.client.show_network(net['id'])
        self.assertGreater(updated2['network']['revision_number'],
                           updated['network']['revision_number'])

    @decorators.idempotent_id('6c256f71-c929-4200-b3dc-4e1843506be5')
    @utils.requires_ext(extension="security-group", service="network")
    def test_update_sg_group_bumps_revision(self):
        sg, name = self._create_security_group()
        self.assertIn('revision_number', sg['security_group'])
        update_body = self.client.update_security_group(
            sg['security_group']['id'], name='new_sg_name')
        self.assertGreater(update_body['security_group']['revision_number'],
                           sg['security_group']['revision_number'])

    @decorators.idempotent_id('6489632f-8550-4453-a674-c98849742967')
    @utils.requires_ext(extension="security-group", service="network")
    def test_update_port_sg_binding_bumps_revision(self):
        net = self.create_network()
        self.addCleanup(self.client.delete_network, net['id'])
        port = self.create_port(net)
        self.addCleanup(self.client.delete_port, port['id'])
        sg = self._create_security_group()[0]
        self.client.update_port(
            port['id'], security_groups=[sg['security_group']['id']])
        updated = self.client.show_port(port['id'])
        updated2 = self.client.update_port(port['id'], security_groups=[])
        self.assertGreater(updated['port']['revision_number'],
                           port['revision_number'])
        self.assertGreater(updated2['port']['revision_number'],
                           updated['port']['revision_number'])

    @decorators.idempotent_id('29c7ab2b-d1d8-425d-8cec-fcf632960f22')
    @utils.requires_ext(extension="security-group", service="network")
    def test_update_sg_rule_bumps_sg_revision(self):
        sg, name = self._create_security_group()
        rule = self.client.create_security_group_rule(
            security_group_id=sg['security_group']['id'],
            protocol='tcp', direction='ingress', ethertype=self.ethertype,
            port_range_min=60, port_range_max=70)
        updated = self.client.show_security_group(sg['security_group']['id'])
        self.assertGreater(updated['security_group']['revision_number'],
                           sg['security_group']['revision_number'])
        self.client.delete_security_group_rule(
            rule['security_group_rule']['id'])
        updated2 = self.client.show_security_group(sg['security_group']['id'])
        self.assertGreater(updated2['security_group']['revision_number'],
                           updated['security_group']['revision_number'])

    @decorators.idempotent_id('db70c285-0365-4fac-9f55-2a0ad8cf55a8')
    @utils.requires_ext(extension="allowed-address-pairs", service="network")
    def test_update_allowed_address_pairs_bumps_revision(self):
        net = self.create_network()
        self.addCleanup(self.client.delete_network, net['id'])
        port = self.create_port(net)
        self.addCleanup(self.client.delete_port, port['id'])
        updated = self.client.update_port(
            port['id'], allowed_address_pairs=[{'ip_address': '1.1.1.1/32'}])
        self.assertGreater(updated['port']['revision_number'],
                           port['revision_number'])
        updated2 = self.client.update_port(
            port['id'], allowed_address_pairs=[])
        self.assertGreater(updated2['port']['revision_number'],
                           updated['port']['revision_number'])

    @decorators.idempotent_id('a21ec3b4-3569-4b77-bf29-4177edaa2df5')
    @utils.requires_ext(extension="extra_dhcp_opt", service="network")
    def test_update_extra_dhcp_opt_bumps_revision(self):
        net = self.create_network()
        self.addCleanup(self.client.delete_network, net['id'])
        port = self.create_port(net)
        self.addCleanup(self.client.delete_port, port['id'])
        opts = [{'opt_value': 'pxelinux.0', 'opt_name': 'bootfile-name'}]
        updated = self.client.update_port(port['id'], extra_dhcp_opts=opts)
        self.assertGreater(updated['port']['revision_number'],
                           port['revision_number'])
        opts[0]['opt_value'] = 'pxelinux.77'
        updated2 = self.client.update_port(
            port['id'], extra_dhcp_opts=opts)
        self.assertGreater(updated2['port']['revision_number'],
                           updated['port']['revision_number'])

    @decorators.idempotent_id('40ba648f-f374-4c29-a5b7-489dd5a38a4e')
    @utils.requires_ext(extension="dns-integration", service="network")
    def test_update_dns_domain_bumps_revision(self):
        net = self.create_network(dns_domain='example.test.')
        self.addCleanup(self.client.delete_network, net['id'])
        updated = self.client.update_network(net['id'], dns_domain='exa.test.')
        self.assertGreater(updated['network']['revision_number'],
                           net['revision_number'])
        port = self.create_port(net)
        self.addCleanup(self.client.delete_port, port['id'])
        updated = self.client.update_port(port['id'], dns_name='port1')
        if not updated['port']['dns_name']:
            self.skipTest("Server does not have DNS domain configured.")
        self.assertGreater(updated['port']['revision_number'],
                           port['revision_number'])
        updated2 = self.client.update_port(port['id'], dns_name='')
        self.assertGreater(updated2['port']['revision_number'],
                           updated['port']['revision_number'])

    @decorators.idempotent_id('8482324f-cf59-4d73-b98e-d37119255300')
    @utils.requires_ext(extension="router", service="network")
    @utils.requires_ext(extension="extraroute", service="network")
    def test_update_router_extra_routes_bumps_revision(self):
        net = self.create_network()
        self.addCleanup(self.client.delete_network, net['id'])
        subnet = self.create_subnet(net)
        self.addCleanup(self.client.delete_subnet, subnet['id'])
        subgateway = netaddr.IPAddress(subnet['gateway_ip'])
        router = self.create_router(router_name='test')
        self.addCleanup(self.client.delete_router, router['id'])
        self.create_router_interface(router['id'], subnet['id'])
        self.addCleanup(
            self.client.remove_router_interface_with_subnet_id,
            router['id'],
            subnet['id'])
        router = self.client.show_router(router['id'])['router']
        updated = self.client.update_extra_routes(
            router['id'], str(subgateway + 1), '2.0.0.0/24')
        self.assertGreater(updated['router']['revision_number'],
                           router['revision_number'])
        updated2 = self.client.delete_extra_routes(router['id'])
        self.assertGreater(updated2['router']['revision_number'],
                           updated['router']['revision_number'])

    @decorators.idempotent_id('6bd18702-e25a-4b4b-8c0c-680113533511')
    @utils.requires_ext(extension="subnet-service-types", service="network")
    def test_update_subnet_service_types_bumps_revisions(self):
        net = self.create_network()
        self.addCleanup(self.client.delete_network, net['id'])
        subnet = self.create_subnet(net)
        self.addCleanup(self.client.delete_subnet, subnet['id'])
        updated = self.client.update_subnet(
            subnet['id'], service_types=['compute:'])
        self.assertGreater(updated['subnet']['revision_number'],
                           subnet['revision_number'])
        updated2 = self.client.update_subnet(
            subnet['id'], service_types=[])
        self.assertGreater(updated2['subnet']['revision_number'],
                           updated['subnet']['revision_number'])

    @decorators.idempotent_id('9c83105c-9973-45ff-9ca2-e66d64700abe')
    @utils.requires_ext(extension="port-security", service="network")
    def test_update_port_security_bumps_revisions(self):
        net = self.create_network(port_security_enabled=False)
        self.addCleanup(self.client.delete_network, net['id'])
        updated = self.client.update_network(net['id'],
                                             port_security_enabled=True)
        self.assertGreater(updated['network']['revision_number'],
                           net['revision_number'])
        updated2 = self.client.update_network(net['id'],
                                              port_security_enabled=False)
        self.assertGreater(updated2['network']['revision_number'],
                           updated['network']['revision_number'])
        port = self.create_port(net, port_security_enabled=False)
        self.addCleanup(self.client.delete_port, port['id'])
        updated = self.client.update_port(port['id'],
                                          port_security_enabled=True)
        self.assertGreater(updated['port']['revision_number'],
                           port['revision_number'])
        updated2 = self.client.update_port(port['id'],
                                           port_security_enabled=False)
        self.assertGreater(updated2['port']['revision_number'],
                           updated['port']['revision_number'])

    @decorators.idempotent_id('68d5ac3a-11a1-4847-8e2e-5843c043d89b')
    @utils.requires_ext(extension="binding", service="network")
    def test_portbinding_bumps_revision(self):
        net = self.create_network()
        self.addCleanup(self.client.delete_network, net['id'])
        port = self.create_port(net)
        self.addCleanup(self.client.delete_port, port['id'])
        port = self.admin_client.update_port(
            port['id'], **{'binding:host_id': 'badhost1'})['port']
        updated = self.admin_client.update_port(
            port['id'], **{'binding:host_id': 'badhost2'})['port']
        self.assertGreater(updated['revision_number'],
                           port['revision_number'])

    @decorators.idempotent_id('4a37bde9-1975-47e0-9b8c-2c9ca36415b0')
    @utils.requires_ext(extension="router", service="network")
    def test_update_router_bumps_revision(self):
        net = self.create_network()
        self.addCleanup(self.client.delete_network, net['id'])
        subnet = self.create_subnet(net)
        self.addCleanup(self.client.delete_subnet, subnet['id'])
        router = self.create_router(router_name='test')
        self.addCleanup(self.client.delete_router, router['id'])
        self.assertIn('revision_number', router)
        rev1 = router['revision_number']
        router = self.client.update_router(router['id'],
                                           name='test2')['router']
        self.assertGreater(router['revision_number'], rev1)
        self.create_router_interface(router['id'], subnet['id'])
        self.addCleanup(
            self.client.remove_router_interface_with_subnet_id,
            router['id'],
            subnet['id'])
        updated = self.client.show_router(router['id'])['router']
        self.assertGreater(updated['revision_number'],
                           router['revision_number'])

    @decorators.idempotent_id('9de71ebc-f5df-4cd0-80bc-60299fce3ce9')
    @utils.requires_ext(extension="router", service="network")
    @utils.requires_ext(extension="standard-attr-description",
                       service="network")
    def test_update_floatingip_bumps_revision(self):
        ext_id = config.CONF.network.public_network_id
        net = self.create_network()
        self.addCleanup(self.client.delete_network, net['id'])
        subnet = self.create_subnet(net)
        self.addCleanup(self.client.delete_subnet, subnet['id'])
        router = self.create_router('test', external_network_id=ext_id)
        self.addCleanup(self.client.delete_router, router['id'])
        self.create_router_interface(router['id'], subnet['id'])
        self.addCleanup(
            self.client.remove_router_interface_with_subnet_id,
            router['id'],
            subnet['id'])
        port = self.create_port(net)
        self.addCleanup(self.client.delete_port, port['id'])
        body = self.client.create_floatingip(
            floating_network_id=ext_id,
            port_id=port['id'],
            description='d1'
        )['floatingip']
        self.floating_ips.append(body)
        self.assertIn('revision_number', body)
        b2 = self.client.update_floatingip(body['id'], description='d2')
        self.assertGreater(b2['floatingip']['revision_number'],
                           body['revision_number'])
        # disassociate
        self.client.update_floatingip(b2['floatingip']['id'], port_id=None)

    @decorators.idempotent_id('afb6486c-41b5-483e-a500-3c506f4deb49')
    @utils.requires_ext(extension="router", service="network")
    @utils.requires_ext(extension="l3-ha", service="network")
    def test_update_router_extra_attributes_bumps_revision(self):
        # updates from CVR to CVR-HA are supported on every release,
        # but only the admin can forcibly create a non-HA router
        router_args = {'tenant_id': self.client.tenant_id,
                       'ha': False}
        router = self.admin_client.create_router('r1', True,
            **router_args)['router']
        self.addCleanup(self.client.delete_router, router['id'])
        self.assertIn('revision_number', router)
        rev1 = router['revision_number']
        router = self.admin_client.update_router(
            router['id'], admin_state_up=False)['router']
        self.assertGreater(router['revision_number'], rev1)
        self.admin_client.update_router(router['id'], ha=True)['router']
        updated = self.client.show_router(router['id'])['router']
        self.assertGreater(updated['revision_number'],
                           router['revision_number'])

    @decorators.idempotent_id('90743b00-b0e2-40e4-9524-1c884fe3ef23')
    @utils.requires_ext(extension="external-net", service="network")
    @utils.requires_ext(extension="auto-allocated-topology", service="network")
    @utils.requires_ext(extension="subnet_allocation", service="network")
    @utils.requires_ext(extension="router", service="network")
    def test_update_external_network_bumps_revision(self):
        net = self.create_network()
        self.addCleanup(self.client.delete_network, net['id'])
        self.assertIn('revision_number', net)
        updated = self.admin_client.update_network(net['id'],
                                                   **{'router:external': True})
        self.assertGreater(updated['network']['revision_number'],
                           net['revision_number'])

    @decorators.idempotent_id('5af6450a-0f61-49c3-b628-38db77c7b856')
    @utils.requires_ext(extension="qos", service="network")
    def test_update_qos_port_policy_binding_bumps_revision(self):
        policy = self.create_qos_policy(name='port-policy', shared=False)
        net = self.create_network()
        self.addCleanup(self.client.delete_network, net['id'])
        port = self.create_port(net)
        self.addCleanup(self.client.delete_port, port['id'])
        updated = self.admin_client.update_port(
            port['id'], qos_policy_id=policy['id'])
        self.assertGreater(updated['port']['revision_number'],
                           port['revision_number'])

    @decorators.idempotent_id('817da343-c6e4-445c-9519-a621f124dfbe')
    @utils.requires_ext(extension="qos", service="network")
    def test_update_qos_network_policy_binding_bumps_revision(self):
        policy = self.create_qos_policy(name='network-policy', shared=False)
        network = self.create_network()
        self.addCleanup(self.client.delete_network, network['id'])
        updated = self.admin_client.update_network(
            network['id'], qos_policy_id=policy['id'])
        self.assertGreater(updated['network']['revision_number'],
                           network['revision_number'])

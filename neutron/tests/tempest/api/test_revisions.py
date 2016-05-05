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

from tempest import test

from neutron.tests.tempest.api import base
from neutron.tests.tempest.api import base_security_groups as bsg
from neutron.tests.tempest import config


class TestRevisions(base.BaseAdminNetworkTest, bsg.BaseSecGroupTest):

    @classmethod
    @test.requires_ext(extension="revisions", service="network")
    def skip_checks(cls):
        super(TestRevisions, cls).skip_checks()

    @test.idempotent_id('4a26a4be-9c53-483c-bc50-b53f1db10ac6')
    def test_update_network_bumps_revision(self):
        net = self.create_network()
        self.assertIn('revision_number', net)
        updated = self.client.update_network(net['id'], name='newnet')
        self.assertGreater(updated['network']['revision_number'],
                           net['revision_number'])

    @test.idempotent_id('cac7ecde-12d5-4331-9a03-420899dea077')
    def test_update_port_bumps_revision(self):
        net = self.create_network()
        port = self.create_port(net)
        self.assertIn('revision_number', port)
        updated = self.client.update_port(port['id'], name='newport')
        self.assertGreater(updated['port']['revision_number'],
                           port['revision_number'])

    @test.idempotent_id('c1c4fa41-8e89-44d0-9bfc-409f3b66dc57')
    def test_update_subnet_bumps_revision(self):
        net = self.create_network()
        subnet = self.create_subnet(net)
        self.assertIn('revision_number', subnet)
        updated = self.client.update_subnet(subnet['id'], name='newsub')
        self.assertGreater(updated['subnet']['revision_number'],
                           subnet['revision_number'])

    @test.idempotent_id('e8c5d7db-2b8d-4615-a476-6e537437c4f2')
    def test_update_subnetpool_bumps_revision(self):
        sp = self.create_subnetpool('subnetpool', default_prefixlen=24,
                                    prefixes=['10.0.0.0/8'])
        self.assertIn('revision_number', sp)
        updated = self.admin_client.update_subnetpool(sp['id'], name='sp2')
        self.assertGreater(updated['subnetpool']['revision_number'],
                           sp['revision_number'])

    @test.idempotent_id('e8c5d7db-2b8d-4567-a326-6e123437c4d1')
    def test_update_subnet_bumps_network_revision(self):
        net = self.create_network()
        subnet = self.create_subnet(net)
        updated = self.client.show_network(net['id'])
        self.assertGreater(updated['network']['revision_number'],
                           net['revision_number'])
        self.client.delete_subnet(subnet['id'])
        updated2 = self.client.show_network(net['id'])
        self.assertGreater(updated2['network']['revision_number'],
                           updated['network']['revision_number'])

    @test.idempotent_id('6c256f71-c929-4200-b3dc-4e1843506be5')
    @test.requires_ext(extension="security-group", service="network")
    def test_update_sg_group_bumps_revision(self):
        sg, name = self._create_security_group()
        self.assertIn('revision_number', sg['security_group'])
        update_body = self.client.update_security_group(
            sg['security_group']['id'], name='new_sg_name')
        self.assertGreater(update_body['security_group']['revision_number'],
                           sg['security_group']['revision_number'])

    @test.idempotent_id('6489632f-8550-4453-a674-c98849742967')
    @test.requires_ext(extension="security-group", service="network")
    def test_update_port_sg_binding_bumps_revision(self):
        net = self.create_network()
        port = self.create_port(net)
        sg = self._create_security_group()[0]
        self.client.update_port(
            port['id'], security_groups=[sg['security_group']['id']])
        updated = self.client.show_port(port['id'])
        self.client.update_port(port['id'], security_groups=[])
        # TODO(kevinbenton): these extra shows after after the update are
        # to work around the fact that ML2 creates the result dict before
        # commit happens if the port is unbound. The update response should
        # be usable directly once that is fixed.
        updated2 = self.client.show_port(port['id'])
        self.assertGreater(updated['port']['revision_number'],
                           port['revision_number'])
        self.assertGreater(updated2['port']['revision_number'],
                           updated['port']['revision_number'])

    @test.idempotent_id('29c7ab2b-d1d8-425d-8cec-fcf632960f22')
    @test.requires_ext(extension="security-group", service="network")
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

    @test.idempotent_id('4a37bde9-1975-47e0-9b8c-2c9ca36415b0')
    @test.requires_ext(extension="router", service="network")
    def test_update_router_bumps_revision(self):
        subnet = self.create_subnet(self.create_network())
        router = self.create_router(router_name='test')
        self.assertIn('revision_number', router)
        rev1 = router['revision_number']
        router = self.client.update_router(router['id'],
                                           name='test2')['router']
        self.assertGreater(router['revision_number'], rev1)
        self.create_router_interface(router['id'], subnet['id'])
        updated = self.client.show_router(router['id'])['router']
        self.assertGreater(updated['revision_number'],
                           router['revision_number'])

    @test.idempotent_id('9de71ebc-f5df-4cd0-80bc-60299fce3ce9')
    @test.requires_ext(extension="router", service="network")
    @test.requires_ext(extension="standard-attr-description",
                       service="network")
    def test_update_floatingip_bumps_revision(self):
        ext_id = config.CONF.network.public_network_id
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router('test', external_network_id=ext_id)
        self.create_router_interface(router['id'], subnet['id'])
        port = self.create_port(network)
        body = self.client.create_floatingip(
            floating_network_id=ext_id,
            port_id=port['id'],
            description='d1'
        )['floatingip']
        self.assertIn('revision_number', body)
        b2 = self.client.update_floatingip(body['id'], description='d2')
        self.assertGreater(b2['floatingip']['revision_number'],
                           body['revision_number'])
        # disassociate
        self.client.update_floatingip(b2['floatingip']['id'], port_id=None)

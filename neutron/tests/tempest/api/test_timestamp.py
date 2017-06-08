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

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from neutron.tests.tempest.api import base
from neutron.tests.tempest.api import base_routers
from neutron.tests.tempest.api import base_security_groups
from neutron.tests.tempest import config

CONF = config.CONF


class TestTimeStamp(base.BaseAdminNetworkTest):

    required_extensions = ["standard-attr-timestamp"]

    ## attributes for subnetpool
    min_prefixlen = '28'
    max_prefixlen = '31'
    _ip_version = 4
    subnet_cidr = '10.11.12.0/31'
    new_prefix = '10.11.15.0/24'
    larger_prefix = '10.11.0.0/16'

    @classmethod
    def resource_setup(cls):
        super(TestTimeStamp, cls).resource_setup()
        prefixes = ['10.11.12.0/24']
        cls._subnetpool_data = {'min_prefixlen': '29', 'prefixes': prefixes}

    def _create_subnetpool(self, is_admin=False, **kwargs):
        name = data_utils.rand_name('subnetpool-')
        subnetpool_data = copy.deepcopy(self._subnetpool_data)
        for key in subnetpool_data.keys():
            kwargs[key] = subnetpool_data[key]
        return self.create_subnetpool(name=name, is_admin=is_admin, **kwargs)

    @decorators.idempotent_id('462be770-b310-4df9-9c42-773217e4c8b1')
    def test_create_network_with_timestamp(self):
        network = self.create_network()
        # Verifies body contains timestamp fields
        self.assertIsNotNone(network['created_at'])
        self.assertIsNotNone(network['updated_at'])

    @decorators.idempotent_id('4db5417a-e11c-474d-a361-af00ebef57c5')
    def test_update_network_with_timestamp(self):
        network = self.create_network()
        origin_updated_at = network['updated_at']
        update_body = {'name': network['name'] + 'new'}
        body = self.admin_client.update_network(network['id'],
                                                **update_body)
        updated_network = body['network']
        new_updated_at = updated_network['updated_at']
        self.assertEqual(network['created_at'], updated_network['created_at'])
        # Verify that origin_updated_at is not same with new_updated_at
        self.assertIsNot(origin_updated_at, new_updated_at)

    @decorators.idempotent_id('2ac50ab2-7ebd-4e27-b3ce-a9e399faaea2')
    def test_show_networks_attribute_with_timestamp(self):
        network = self.create_network()
        body = self.client.show_network(network['id'])
        show_net = body['network']
        # verify the timestamp from creation and showed is same
        self.assertEqual(network['created_at'],
                         show_net['created_at'])
        self.assertEqual(network['updated_at'],
                         show_net['updated_at'])

    @decorators.idempotent_id('8ee55186-454f-4b97-9f9f-eb2772ee891c')
    def test_create_subnet_with_timestamp(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        # Verifies body contains timestamp fields
        self.assertIsNotNone(subnet['created_at'])
        self.assertIsNotNone(subnet['updated_at'])

    @decorators.idempotent_id('a490215a-6f4c-4af9-9a4c-57c41f1c4fa1')
    def test_update_subnet_with_timestamp(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        origin_updated_at = subnet['updated_at']
        update_body = {'name': subnet['name'] + 'new'}
        body = self.admin_client.update_subnet(subnet['id'],
                                               **update_body)
        updated_subnet = body['subnet']
        new_updated_at = updated_subnet['updated_at']
        self.assertEqual(subnet['created_at'], updated_subnet['created_at'])
        # Verify that origin_updated_at is not same with new_updated_at
        self.assertIsNot(origin_updated_at, new_updated_at)

    @decorators.idempotent_id('1836a086-e7cf-4141-bf57-0cfe79e8051e')
    def test_show_subnet_attribute_with_timestamp(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        body = self.client.show_subnet(subnet['id'])
        show_subnet = body['subnet']
        # verify the timestamp from creation and showed is same
        self.assertEqual(subnet['created_at'],
                         show_subnet['created_at'])
        self.assertEqual(subnet['updated_at'],
                         show_subnet['updated_at'])

    @decorators.idempotent_id('e2450a7b-d84f-4600-a093-45e78597bbac')
    def test_create_port_with_timestamp(self):
        network = self.create_network()
        port = self.create_port(network)
        # Verifies body contains timestamp fields
        self.assertIsNotNone(port['created_at'])
        self.assertIsNotNone(port['updated_at'])

    @decorators.idempotent_id('4241e0d3-54b4-46ce-a9a7-093fc764161b')
    def test_update_port_with_timestamp(self):
        network = self.create_network()
        port = self.create_port(network)
        origin_updated_at = port['updated_at']
        update_body = {'name': port['name'] + 'new'}
        body = self.admin_client.update_port(port['id'],
                                             **update_body)
        updated_port = body['port']
        new_updated_at = updated_port['updated_at']
        self.assertEqual(port['created_at'], updated_port['created_at'])
        # Verify that origin_updated_at is not same with new_updated_at
        self.assertIsNot(origin_updated_at, new_updated_at)

    @decorators.idempotent_id('584c6723-40b6-4f26-81dd-f508f9d9fb51')
    def test_show_port_attribute_with_timestamp(self):
        network = self.create_network()
        port = self.create_port(network)
        body = self.client.show_port(port['id'])
        show_port = body['port']
        # verify the timestamp from creation and showed is same
        self.assertEqual(port['created_at'],
                         show_port['created_at'])
        self.assertEqual(port['updated_at'],
                         show_port['updated_at'])

    @decorators.idempotent_id('87a8b196-4b90-44f0-b7f3-d2057d7d658e')
    def test_create_subnetpool_with_timestamp(self):
        sp = self._create_subnetpool()
        # Verifies body contains timestamp fields
        self.assertIsNotNone(sp['created_at'])
        self.assertIsNotNone(sp['updated_at'])

    @decorators.idempotent_id('d48c7578-c3d2-4f9b-a7a1-be2008c770a0')
    def test_update_subnetpool_with_timestamp(self):
        sp = self._create_subnetpool()
        origin_updated_at = sp['updated_at']
        update_body = {'name': sp['name'] + 'new',
                       'min_prefixlen': self.min_prefixlen,
                       'max_prefixlen': self.max_prefixlen}
        body = self.client.update_subnetpool(sp['id'], **update_body)
        updated_sp = body['subnetpool']
        new_updated_at = updated_sp['updated_at']
        self.assertEqual(sp['created_at'], updated_sp['created_at'])
        # Verify that origin_updated_at is not same with new_updated_at
        self.assertIsNot(origin_updated_at, new_updated_at)

    @decorators.idempotent_id('1d3970e6-bcf7-46cd-b7d7-0807759c73b4')
    def test_show_subnetpool_attribute_with_timestamp(self):
        sp = self._create_subnetpool()
        body = self.client.show_subnetpool(sp['id'])
        show_sp = body['subnetpool']
        # verify the timestamp from creation and showed is same
        self.assertEqual(sp['created_at'], show_sp['created_at'])
        self.assertEqual(sp['updated_at'], show_sp['updated_at'])


class TestTimeStampWithL3(base_routers.BaseRouterTest):

    required_extensions = ['standard-attr-timestamp']

    @classmethod
    def resource_setup(cls):
        super(TestTimeStampWithL3, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id

    @decorators.idempotent_id('433ba770-b310-4da9-5d42-733217a1c7b1')
    def test_create_router_with_timestamp(self):
        router = self.create_router(router_name='test')
        # Verifies body contains timestamp fields
        self.assertIsNotNone(router['created_at'])
        self.assertIsNotNone(router['updated_at'])

    @decorators.idempotent_id('4a65417a-c11c-4b4d-a351-af01abcf57c6')
    def test_update_router_with_timestamp(self):
        router = self.create_router(router_name='test')
        origin_updated_at = router['updated_at']
        update_body = {'name': router['name'] + 'new'}
        body = self.client.update_router(router['id'], **update_body)
        updated_router = body['router']
        new_updated_at = updated_router['updated_at']
        self.assertEqual(router['created_at'], updated_router['created_at'])
        # Verify that origin_updated_at is not same with new_updated_at
        self.assertIsNot(origin_updated_at, new_updated_at)

    @decorators.idempotent_id('1ab50ac2-7cbd-4a17-b23e-a9e36cfa4ec2')
    def test_show_router_attribute_with_timestamp(self):
        router = self.create_router(router_name='test')
        body = self.client.show_router(router['id'])
        show_router = body['router']
        # verify the timestamp from creation and showed is same
        self.assertEqual(router['created_at'],
                         show_router['created_at'])
        # 'updated_at' timestamp can change immediately after creation
        # if environment is HA or DVR, so just make sure it's >=
        self.assertGreaterEqual(show_router['updated_at'],
                                router['updated_at'])

    @decorators.idempotent_id('8ae55186-464f-4b87-1c9f-eb2765ee81ac')
    def test_create_floatingip_with_timestamp(self):
        fip = self.create_floatingip(self.ext_net_id)
        # Verifies body contains timestamp fields
        self.assertIsNotNone(fip['created_at'])
        self.assertIsNotNone(fip['updated_at'])

    @decorators.idempotent_id('a3ac215a-61ac-13f9-9d3c-57c51f11afa1')
    def test_update_floatingip_with_timestamp(self):
        fip = self.create_floatingip(self.ext_net_id)
        origin_updated_at = fip['updated_at']
        update_body = {'description': 'new'}
        body = self.client.update_floatingip(fip['id'], **update_body)
        updated_fip = body['floatingip']
        new_updated_at = updated_fip['updated_at']
        self.assertEqual(fip['created_at'], updated_fip['created_at'])
        # Verify that origin_updated_at is not same with new_updated_at
        self.assertIsNot(origin_updated_at, new_updated_at)

    @decorators.idempotent_id('32a6a086-e1ef-413b-b13a-0cfe13ef051e')
    def test_show_floatingip_attribute_with_timestamp(self):
        fip = self.create_floatingip(self.ext_net_id)
        body = self.client.show_floatingip(fip['id'])
        show_fip = body['floatingip']
        # verify the timestamp from creation and showed is same
        self.assertEqual(fip['created_at'],
                         show_fip['created_at'])
        self.assertEqual(fip['updated_at'],
                         show_fip['updated_at'])


class TestTimeStampWithSecurityGroup(base_security_groups.BaseSecGroupTest):

    required_extensions = ['standard-attr-timestamp']

    @classmethod
    def resource_setup(cls):
        super(TestTimeStampWithSecurityGroup, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id

    @decorators.idempotent_id('a3150a7b-d31a-423a-abf3-45e71c97cbac')
    def test_create_sg_with_timestamp(self):
        sg, _ = self._create_security_group()
        # Verifies body contains timestamp fields
        self.assertIsNotNone(sg['security_group']['created_at'])
        self.assertIsNotNone(sg['security_group']['updated_at'])

    @decorators.idempotent_id('432ae0d3-32b4-413e-a9b3-091ac76da31b')
    def test_update_sg_with_timestamp(self):
        sgc, _ = self._create_security_group()
        sg = sgc['security_group']
        origin_updated_at = sg['updated_at']
        update_body = {'name': sg['name'] + 'new'}
        body = self.client.update_security_group(sg['id'], **update_body)
        updated_sg = body['security_group']
        new_updated_at = updated_sg['updated_at']
        self.assertEqual(sg['created_at'], updated_sg['created_at'])
        # Verify that origin_updated_at is not same with new_updated_at
        self.assertIsNot(origin_updated_at, new_updated_at)

    @decorators.idempotent_id('521e6723-43d6-12a6-8c3d-f5042ad9fc32')
    def test_show_sg_attribute_with_timestamp(self):
        sg, _ = self._create_security_group()
        body = self.client.show_security_group(sg['security_group']['id'])
        show_sg = body['security_group']
        # verify the timestamp from creation and showed is same
        self.assertEqual(sg['security_group']['created_at'],
                         show_sg['created_at'])
        self.assertEqual(sg['security_group']['updated_at'],
                         show_sg['updated_at'])

    def _prepare_sgrule_test(self):
        sg, _ = self._create_security_group()
        sg_id = sg['security_group']['id']
        direction = 'ingress'
        protocol = 'tcp'
        port_range_min = 77
        port_range_max = 77
        rule_create_body = self.client.create_security_group_rule(
            security_group_id=sg_id,
            direction=direction,
            ethertype=self.ethertype,
            protocol=protocol,
            port_range_min=port_range_min,
            port_range_max=port_range_max,
            remote_group_id=None,
            remote_ip_prefix=None
        )
        return rule_create_body['security_group_rule']

    @decorators.idempotent_id('83e8bd32-43e0-a3f0-1af3-12a5733c653e')
    def test_create_sgrule_with_timestamp(self):
        sgrule = self._prepare_sgrule_test()
        # Verifies body contains timestamp fields
        self.assertIsNotNone(sgrule['created_at'])
        self.assertIsNotNone(sgrule['updated_at'])

    @decorators.idempotent_id('143da0e6-ba17-43ad-b3d7-03aa759c3cb4')
    def test_show_sgrule_attribute_with_timestamp(self):
        sgrule = self._prepare_sgrule_test()
        body = self.client.show_security_group_rule(sgrule['id'])
        show_sgrule = body['security_group_rule']
        # verify the timestamp from creation and showed is same
        self.assertEqual(sgrule['created_at'], show_sgrule['created_at'])
        self.assertEqual(sgrule['updated_at'], show_sgrule['updated_at'])

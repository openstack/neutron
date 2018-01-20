# Copyright 2016 Hewlett Packard Enterprise Development Company LP
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

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron.tests.tempest.api import base
from neutron.tests.tempest import config


def trunks_cleanup(client, trunks):
    for trunk in trunks:
        # NOTE(armax): deleting a trunk with subports is permitted, however
        # for testing purposes it is safer to be explicit and clean all the
        # resources associated with the trunk beforehand.
        subports = test_utils.call_and_ignore_notfound_exc(
            client.get_subports, trunk['id'])
        if subports:
            client.remove_subports(
                trunk['id'], subports['sub_ports'])
        test_utils.call_and_ignore_notfound_exc(
            client.delete_trunk, trunk['id'])


class TrunkTestJSONBase(base.BaseAdminNetworkTest):

    required_extensions = ['trunk']

    def setUp(self):
        self.addCleanup(self.resource_cleanup)
        super(TrunkTestJSONBase, self).setUp()

    @classmethod
    def resource_setup(cls):
        super(TrunkTestJSONBase, cls).resource_setup()
        cls.trunks = []

    @classmethod
    def resource_cleanup(cls):
        trunks_cleanup(cls.client, cls.trunks)
        super(TrunkTestJSONBase, cls).resource_cleanup()

    @classmethod
    def is_type_driver_enabled(cls, type_driver):
        return (type_driver in
                config.CONF.neutron_plugin_options.available_type_drivers)

    def _create_trunk_with_network_and_parent(
            self, subports, parent_network_type=None, **kwargs):
        client = None
        network_kwargs = {}
        if parent_network_type:
            client = self.admin_client
            network_kwargs = {"provider:network_type": parent_network_type,
                              "tenant_id": self.client.tenant_id}
        network = self.create_network(client=client, **network_kwargs)
        parent_port = self.create_port(network)
        trunk = self.client.create_trunk(parent_port['id'], subports, **kwargs)
        self.trunks.append(trunk['trunk'])
        return trunk

    def _show_trunk(self, trunk_id):
        return self.client.show_trunk(trunk_id)

    def _list_trunks(self):
        return self.client.list_trunks()


class TrunkTestJSON(TrunkTestJSONBase):

    def _test_create_trunk(self, subports):
        trunk = self._create_trunk_with_network_and_parent(subports)
        observed_trunk = self._show_trunk(trunk['trunk']['id'])
        self.assertEqual(trunk, observed_trunk)

    @decorators.idempotent_id('e1a6355c-4768-41f3-9bf8-0f1d192bd501')
    def test_create_trunk_empty_subports_list(self):
        self._test_create_trunk([])

    @decorators.idempotent_id('382dfa39-ca03-4bd3-9a1c-91e36d2e3796')
    def test_create_trunk_subports_not_specified(self):
        self._test_create_trunk(None)

    @decorators.idempotent_id('7de46c22-e2b6-4959-ac5a-0e624632ab32')
    def test_create_show_delete_trunk(self):
        trunk = self._create_trunk_with_network_and_parent(None)
        trunk_id = trunk['trunk']['id']
        parent_port_id = trunk['trunk']['port_id']
        res = self._show_trunk(trunk_id)
        self.assertEqual(trunk_id, res['trunk']['id'])
        self.assertEqual(parent_port_id, res['trunk']['port_id'])
        self.client.delete_trunk(trunk_id)
        self.assertRaises(lib_exc.NotFound, self._show_trunk, trunk_id)

    @decorators.idempotent_id('8d83a6ca-662d-45b8-8062-d513077296aa')
    @utils.requires_ext(extension="project-id", service="network")
    def test_show_trunk_has_project_id(self):
        trunk = self._create_trunk_with_network_and_parent(None)
        body = self._show_trunk(trunk['trunk']['id'])
        show_trunk = body['trunk']
        self.assertIn('project_id', show_trunk)
        self.assertIn('tenant_id', show_trunk)
        self.assertEqual(self.client.tenant_id, show_trunk['project_id'])
        self.assertEqual(self.client.tenant_id, show_trunk['tenant_id'])

    @decorators.idempotent_id('4ce46c22-a2b6-4659-bc5a-0ef2463cab32')
    def test_create_update_trunk(self):
        trunk = self._create_trunk_with_network_and_parent(None)
        rev = trunk['trunk']['revision_number']
        trunk_id = trunk['trunk']['id']
        res = self._show_trunk(trunk_id)
        self.assertTrue(res['trunk']['admin_state_up'])
        self.assertEqual(rev, res['trunk']['revision_number'])
        self.assertEqual("", res['trunk']['name'])
        self.assertEqual("", res['trunk']['description'])
        res = self.client.update_trunk(
            trunk_id, name='foo', admin_state_up=False)
        self.assertFalse(res['trunk']['admin_state_up'])
        self.assertEqual("foo", res['trunk']['name'])
        self.assertGreater(res['trunk']['revision_number'], rev)
        # enable the trunk so that it can be managed
        self.client.update_trunk(trunk_id, admin_state_up=True)

    @decorators.idempotent_id('5ff46c22-a2b6-5559-bc5a-0ef2463cab32')
    def test_create_update_trunk_with_description(self):
        trunk = self._create_trunk_with_network_and_parent(
            None, description="foo description")
        trunk_id = trunk['trunk']['id']
        self.assertEqual("foo description", trunk['trunk']['description'])
        trunk = self.client.update_trunk(trunk_id, description='')
        self.assertEqual('', trunk['trunk']['description'])

    @decorators.idempotent_id('73365f73-bed6-42cd-960b-ec04e0c99d85')
    def test_list_trunks(self):
        trunk1 = self._create_trunk_with_network_and_parent(None)
        trunk2 = self._create_trunk_with_network_and_parent(None)
        expected_trunks = {trunk1['trunk']['id']: trunk1['trunk'],
                           trunk2['trunk']['id']: trunk2['trunk']}
        trunk_list = self._list_trunks()['trunks']
        matched_trunks = [x for x in trunk_list if x['id'] in expected_trunks]
        self.assertEqual(2, len(matched_trunks))
        for trunk in matched_trunks:
            self.assertEqual(expected_trunks[trunk['id']], trunk)

    @decorators.idempotent_id('bb5fcead-09b5-484a-bbe6-46d1e06d6cc0')
    def test_add_subport(self):
        trunk = self._create_trunk_with_network_and_parent([])
        network = self.create_network()
        port = self.create_port(network)
        subports = [{'port_id': port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]
        self.client.add_subports(trunk['trunk']['id'], subports)
        trunk = self._show_trunk(trunk['trunk']['id'])
        observed_subports = trunk['trunk']['sub_ports']
        self.assertEqual(1, len(observed_subports))
        created_subport = observed_subports[0]
        self.assertEqual(subports[0], created_subport)

    @decorators.idempotent_id('ee5fcead-1abf-483a-bce6-43d1e06d6aa0')
    def test_delete_trunk_with_subport_is_allowed(self):
        network = self.create_network()
        port = self.create_port(network)
        subports = [{'port_id': port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]
        trunk = self._create_trunk_with_network_and_parent(subports)
        self.client.delete_trunk(trunk['trunk']['id'])

    @decorators.idempotent_id('96eea398-a03c-4c3e-a99e-864392c2ca53')
    def test_remove_subport(self):
        subport_parent1 = self.create_port(self.create_network())
        subport_parent2 = self.create_port(self.create_network())
        subports = [{'port_id': subport_parent1['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2},
                    {'port_id': subport_parent2['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 4}]
        trunk = self._create_trunk_with_network_and_parent(subports)
        removed_subport = trunk['trunk']['sub_ports'][0]
        expected_subport = None

        for subport in subports:
            if subport['port_id'] != removed_subport['port_id']:
                expected_subport = subport
                break

        # Remove the subport and validate PUT response
        res = self.client.remove_subports(trunk['trunk']['id'],
                                          [removed_subport])
        self.assertEqual(1, len(res['sub_ports']))
        self.assertEqual(expected_subport, res['sub_ports'][0])

        # Validate the results of a subport list
        trunk = self._show_trunk(trunk['trunk']['id'])
        observed_subports = trunk['trunk']['sub_ports']
        self.assertEqual(1, len(observed_subports))
        self.assertEqual(expected_subport, observed_subports[0])

    @decorators.idempotent_id('bb5fcaad-09b5-484a-dde6-4cd1ea6d6ff0')
    def test_get_subports(self):
        network = self.create_network()
        port = self.create_port(network)
        subports = [{'port_id': port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]
        trunk = self._create_trunk_with_network_and_parent(subports)
        trunk = self.client.get_subports(trunk['trunk']['id'])
        observed_subports = trunk['sub_ports']
        self.assertEqual(1, len(observed_subports))


class TrunkTestInheritJSONBase(TrunkTestJSONBase):

    required_extensions = ['provider', 'trunk']

    @classmethod
    def skip_checks(cls):
        super(TrunkTestInheritJSONBase, cls).skip_checks()
        if ("vlan" not in
                config.CONF.neutron_plugin_options.available_type_drivers):
            raise cls.skipException("VLAN type_driver is not enabled")
        if not config.CONF.neutron_plugin_options.provider_vlans:
            raise cls.skipException("No provider VLAN networks available")

    def create_provider_network(self):
        foo_net = config.CONF.neutron_plugin_options.provider_vlans[0]
        post_body = {'network_name': data_utils.rand_name('vlan-net-'),
                     'provider:network_type': 'vlan',
                     'provider:physical_network': foo_net}
        return self.create_shared_network(**post_body)

    @decorators.idempotent_id('0f05d98e-41f5-4629-dada-9aee269c9602')
    def test_add_subport(self):
        trunk_network = self.create_provider_network()
        trunk_port = self.create_port(trunk_network)
        subport_networks = [
            self.create_provider_network(),
            self.create_provider_network(),
        ]
        subport1 = self.create_port(subport_networks[0])
        subport2 = self.create_port(subport_networks[1])
        subports = [{'port_id': subport1['id'],
                     'segmentation_type': 'inherit',
                     'segmentation_id': subport1['id']},
                    {'port_id': subport2['id'],
                     'segmentation_type': 'inherit',
                     'segmentation_id': subport2['id']}]
        trunk = self.client.create_trunk(trunk_port['id'], subports)['trunk']
        self.trunks.append(trunk)
        # Validate that subport got segmentation details from the network
        for i in range(2):
            self.assertEqual(subport_networks[i]['provider:network_type'],
                             trunk['sub_ports'][i]['segmentation_type'])
            self.assertEqual(subport_networks[i]['provider:segmentation_id'],
                             trunk['sub_ports'][i]['segmentation_id'])


class TrunkTestMtusJSONBase(TrunkTestJSONBase):

    required_extensions = ['provider', 'trunk']

    @classmethod
    def skip_checks(cls):
        super(TrunkTestMtusJSONBase, cls).skip_checks()
        if not all(cls.is_type_driver_enabled(t) for t in ['gre', 'vxlan']):
            msg = "Either vxlan or gre type driver not enabled."
            raise cls.skipException(msg)

    def setUp(self):
        super(TrunkTestMtusJSONBase, self).setUp()

        # VXLAN autocomputed MTU (1450) is smaller than that of GRE (1458)
        vxlan_kwargs = {'network_name': data_utils.rand_name('vxlan-net-'),
                        'provider:network_type': 'vxlan'}
        self.smaller_mtu_net = self.create_shared_network(**vxlan_kwargs)

        gre_kwargs = {'network_name': data_utils.rand_name('gre-net-'),
                      'provider:network_type': 'gre'}
        self.larger_mtu_net = self.create_shared_network(**gre_kwargs)

        self.smaller_mtu_port = self.create_port(self.smaller_mtu_net)
        self.smaller_mtu_port_2 = self.create_port(self.smaller_mtu_net)
        self.larger_mtu_port = self.create_port(self.larger_mtu_net)


class TrunkTestMtusJSON(TrunkTestMtusJSONBase):

    @decorators.idempotent_id('0f05d98e-41f5-4629-ac29-9aee269c9602')
    def test_create_trunk_with_mtu_greater_than_subport(self):
        subports = [{'port_id': self.smaller_mtu_port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]

        trunk = self.client.create_trunk(self.larger_mtu_port['id'], subports)
        self.trunks.append(trunk['trunk'])

    @decorators.idempotent_id('2004c5c6-e557-4c43-8100-c820ad4953e8')
    def test_add_subport_with_mtu_smaller_than_trunk(self):
        subports = [{'port_id': self.smaller_mtu_port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]

        trunk = self.client.create_trunk(self.larger_mtu_port['id'], None)
        self.trunks.append(trunk['trunk'])

        self.client.add_subports(trunk['trunk']['id'], subports)

    @decorators.idempotent_id('22725101-f4bc-4e00-84ec-4e02cd7e0500')
    def test_create_trunk_with_mtu_equal_to_subport(self):
        subports = [{'port_id': self.smaller_mtu_port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]

        trunk = self.client.create_trunk(self.smaller_mtu_port_2['id'],
                                         subports)
        self.trunks.append(trunk['trunk'])

    @decorators.idempotent_id('175b05ae-66ad-44c7-857a-a12d16f1058f')
    def test_add_subport_with_mtu_equal_to_trunk(self):
        subports = [{'port_id': self.smaller_mtu_port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]

        trunk = self.client.create_trunk(self.smaller_mtu_port_2['id'], None)
        self.trunks.append(trunk['trunk'])

        self.client.add_subports(trunk['trunk']['id'], subports)


class TrunksSearchCriteriaTest(base.BaseSearchCriteriaTest):

    required_extensions = ['trunk']
    resource = 'trunk'

    @classmethod
    def resource_setup(cls):
        super(TrunksSearchCriteriaTest, cls).resource_setup()
        cls.trunks = []
        net = cls.create_network(network_name='trunk-search-test-net')
        for name in cls.resource_names:
            parent_port = cls.create_port(net)
            trunk = cls.client.create_trunk(parent_port['id'], [], name=name)
            cls.trunks.append(trunk['trunk'])

    @classmethod
    def resource_cleanup(cls):
        trunks_cleanup(cls.client, cls.trunks)
        super(TrunksSearchCriteriaTest, cls).resource_cleanup()

    @decorators.idempotent_id('fab73df4-960a-4ae3-87d3-60992b8d3e2d')
    def test_list_sorts_asc(self):
        self._test_list_sorts_asc()

    @decorators.idempotent_id('a426671d-7270-430f-82ff-8f33eec93010')
    def test_list_sorts_desc(self):
        self._test_list_sorts_desc()

    @decorators.idempotent_id('b202fdc8-6616-45df-b6a0-463932de6f94')
    def test_list_pagination(self):
        self._test_list_pagination()

    @decorators.idempotent_id('c4723b8e-8186-4b9a-bf9e-57519967e048')
    def test_list_pagination_with_marker(self):
        self._test_list_pagination_with_marker()

    @decorators.idempotent_id('dcd02a7a-f07e-4d5e-b0ca-b58e48927a9b')
    def test_list_pagination_with_href_links(self):
        self._test_list_pagination_with_href_links()

    @decorators.idempotent_id('eafe7024-77ab-4cfe-824b-0b2bf4217727')
    def test_list_no_pagination_limit_0(self):
        self._test_list_no_pagination_limit_0()

    @decorators.idempotent_id('f8857391-dc44-40cc-89b7-2800402e03ce')
    def test_list_pagination_page_reverse_asc(self):
        self._test_list_pagination_page_reverse_asc()

    @decorators.idempotent_id('ae51e9c9-ceae-4ec0-afd4-147569247699')
    def test_list_pagination_page_reverse_desc(self):
        self._test_list_pagination_page_reverse_desc()

    @decorators.idempotent_id('b4293e59-d794-4a93-be09-38667199ef68')
    def test_list_pagination_page_reverse_with_href_links(self):
        self._test_list_pagination_page_reverse_with_href_links()

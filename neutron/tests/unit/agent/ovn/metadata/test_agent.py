# Copyright 2017 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
from unittest import mock
import uuid

from neutron_lib import constants as n_const
from oslo_config import cfg
from oslo_config import fixture as config_fixture
from oslo_utils import uuidutils

from neutron.agent.linux import ip_lib
from neutron.agent.linux.ip_lib import IpAddrCommand as ip_addr
from neutron.agent.linux.ip_lib import IpLinkCommand as ip_link
from neutron.agent.linux.ip_lib import IpNetnsCommand as ip_netns
from neutron.agent.linux.ip_lib import IPWrapper as ip_wrap
from neutron.agent.ovn.metadata import agent
from neutron.agent.ovn.metadata import driver
from neutron.conf.agent.metadata import config as meta_conf
from neutron.conf.agent.ovn.metadata import config as ovn_meta_conf
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.tests import base


OvnPortInfo = collections.namedtuple(
    'OvnPortInfo', ['datapath', 'type', 'mac', 'external_ids', 'logical_port'])


class DatapathInfo:
    def __init__(self, uuid, external_ids):
        self.uuid = uuid
        self.external_ids = external_ids

    def __hash__(self):
        return hash(self.uuid)


def makePort(datapath=None, type='', mac=None, external_ids=None,
             logical_port=None):
    return OvnPortInfo(datapath, type, mac, external_ids, logical_port)


class ConfFixture(config_fixture.Config):
    def setUp(self):
        super(ConfFixture, self).setUp()
        ovn_meta_conf.register_meta_conf_opts(meta_conf.SHARED_OPTS, self.conf)
        ovn_meta_conf.register_meta_conf_opts(
            meta_conf.UNIX_DOMAIN_METADATA_PROXY_OPTS, self.conf)
        ovn_meta_conf.register_meta_conf_opts(
            meta_conf.METADATA_PROXY_HANDLER_OPTS, self.conf)
        ovn_meta_conf.register_meta_conf_opts(
            ovn_meta_conf.OVS_OPTS, self.conf, group='ovs')
        ovn_conf.register_opts()


class TestMetadataAgent(base.BaseTestCase):
    fake_conf = cfg.CONF
    fake_conf_fixture = ConfFixture(fake_conf)

    def setUp(self):
        super(TestMetadataAgent, self).setUp()
        self.useFixture(self.fake_conf_fixture)
        self.log_p = mock.patch.object(agent, 'LOG')
        self.log = self.log_p.start()
        self.agent = agent.MetadataAgent(self.fake_conf)
        self.agent.sb_idl = mock.Mock()
        self.agent.ovs_idl = mock.Mock()
        self.agent.ovs_idl.transaction = mock.MagicMock()
        self.agent.chassis = 'chassis'
        self.agent.ovn_bridge = 'br-int'

        self.ports = []
        for i in range(0, 3):
            self.ports.append(makePort(
                datapath=DatapathInfo(uuid=str(uuid.uuid4()),
                external_ids={'name': 'neutron-%d' % i})))
        self.agent.sb_idl.get_ports_on_chassis.return_value = self.ports

    def test_sync(self):

        with mock.patch.object(
                self.agent, 'provision_datapath') as pdp,\
                mock.patch.object(
                    ip_lib, 'list_network_namespaces') as lnn,\
                mock.patch.object(
                    self.agent, 'teardown_datapath') as tdp:
            lnn.return_value = ['ovnmeta-1', 'ovnmeta-2']

            self.agent.sync()

            pdp.assert_has_calls(
                [
                    mock.call(p.datapath)
                    for p in self.ports
                ],
                any_order=True
            )

            lnn.assert_called_once_with()
            tdp.assert_not_called()

    def test_sync_teardown_namespace(self):
        """Test that sync tears down unneeded metadata namespaces."""
        with mock.patch.object(
                self.agent, 'provision_datapath') as pdp,\
                mock.patch.object(
                    ip_lib, 'list_network_namespaces') as lnn,\
                mock.patch.object(
                    self.agent, 'teardown_datapath') as tdp:
            lnn.return_value = ['ovnmeta-1', 'ovnmeta-2', 'ovnmeta-3',
                                'ns1', 'ns2']

            self.agent.sync()

            pdp.assert_has_calls(
                [
                    mock.call(p.datapath)
                    for p in self.ports
                ],
                any_order=True
            )
            lnn.assert_called_once_with()
            tdp.assert_called_once_with('3')

    def test_get_networks_datapaths(self):
        """Test get_networks_datapaths returns only datapath objects for the
        networks containing vif ports of type ''(blank) and 'external'.
        This test simulates that this chassis has the following ports:
            * datapath '1': 1 port type '' , 1 port 'external' and
                            1 port 'unknown'
            * datapath '2': 1 port type ''
            * datapath '3': 1 port with type 'external'
            * datapath '4': 1 port with type 'unknown'

        It is expected that only datapaths '1', '2' and '3' are returned
        """

        datapath_1 = DatapathInfo(uuid='uuid1',
            external_ids={'name': 'neutron-1'})
        datapath_2 = DatapathInfo(uuid='uuid2',
            external_ids={'name': 'neutron-2'})
        datapath_3 = DatapathInfo(uuid='uuid3',
            external_ids={'name': 'neutron-3'})
        datapath_4 = DatapathInfo(uuid='uuid4',
            external_ids={'name': 'neutron-4'})

        ports = [
            makePort(datapath_1, type=''),
            makePort(datapath_1, type='external'),
            makePort(datapath_1, type='unknown'),
            makePort(datapath_2, type=''),
            makePort(datapath_3, type='external'),
            makePort(datapath_4, type='unknown')
        ]

        with mock.patch.object(self.agent.sb_idl, 'get_ports_on_chassis',
                              return_value=ports):
            expected_datapaths = set([datapath_1, datapath_2, datapath_3])
            self.assertSetEqual(
                expected_datapaths,
                self.agent.get_networks_datapaths()
            )

    def test_teardown_datapath(self):
        """Test teardown datapath.

        Check that the VETH pair, OVS port and namespace associated to this
        namespace are deleted and the metadata proxy is destroyed.
        """
        with mock.patch.object(ip_netns, 'exists', return_value=True),\
                mock.patch.object(
                    ip_lib, 'device_exists', return_value=True),\
                mock.patch.object(
                    ip_wrap, 'garbage_collect_namespace') as garbage_collect,\
                mock.patch.object(
                    ip_wrap, 'del_veth') as del_veth,\
                mock.patch.object(agent.MetadataAgent, '_get_veth_name',
                                  return_value=['veth_0', 'veth_1']),\
                mock.patch.object(
                    driver.MetadataDriver,
                    'destroy_monitored_metadata_proxy') as destroy_mdp:

            self.agent.teardown_datapath('1')

            destroy_mdp.assert_called_once_with(
                mock.ANY, '1', mock.ANY, 'ovnmeta-1')
            self.agent.ovs_idl.del_port.assert_called_once_with('veth_0')
            del_veth.assert_called_once_with('veth_0')
            garbage_collect.assert_called_once_with()

    def test__process_cidrs_when_current_namespace_empty(self):
        current_namespace_cidrs = set()
        datapath_port_ips = ['10.0.0.2', '10.0.0.3', '10.0.1.5']
        metadaport_subnet_cidrs = ['10.0.0.0/30', '10.0.1.0/28', '11.0.1.2/24']

        expected_cidrs_to_add = set(['10.0.0.0/30', '10.0.1.0/28',
                                     n_const.METADATA_CIDR])
        expected_cidrs_to_delete = set()

        actual_result = self.agent._process_cidrs(current_namespace_cidrs,
                                                  datapath_port_ips,
                                                  metadaport_subnet_cidrs)
        actual_cidrs_to_add, actual_cidrs_to_delete = actual_result

        self.assertSetEqual(actual_cidrs_to_add, expected_cidrs_to_add)
        self.assertSetEqual(actual_cidrs_to_delete, expected_cidrs_to_delete)

    def test__process_cidrs_when_current_namespace_only_contains_metadata_cidr(
            self):
        current_namespace_cidrs = set([n_const.METADATA_CIDR])
        datapath_port_ips = ['10.0.0.2', '10.0.0.3', '10.0.1.5']
        metadaport_subnet_cidrs = ['10.0.0.0/30', '10.0.1.0/28', '11.0.1.2/24']

        expected_cidrs_to_add = set(['10.0.0.0/30', '10.0.1.0/28'])
        expected_cidrs_to_delete = set()

        actual_result = self.agent._process_cidrs(current_namespace_cidrs,
                                                  datapath_port_ips,
                                                  metadaport_subnet_cidrs)
        actual_cidrs_to_add, actual_cidrs_to_delete = actual_result

        self.assertSetEqual(actual_cidrs_to_add, expected_cidrs_to_add)
        self.assertSetEqual(actual_cidrs_to_delete, expected_cidrs_to_delete)

    def test__process_cidrs_when_current_namespace_contains_stale_cidr(self):
        current_namespace_cidrs = set([n_const.METADATA_CIDR, '10.0.1.0/31'])
        datapath_port_ips = ['10.0.0.2', '10.0.0.3', '10.0.1.5']
        metadaport_subnet_cidrs = ['10.0.0.0/30', '10.0.1.0/28', '11.0.1.2/24']

        expected_cidrs_to_add = set(['10.0.0.0/30', '10.0.1.0/28'])
        expected_cidrs_to_delete = set(['10.0.1.0/31'])

        actual_result = self.agent._process_cidrs(current_namespace_cidrs,
                                                  datapath_port_ips,
                                                  metadaport_subnet_cidrs)
        actual_cidrs_to_add, actual_cidrs_to_delete = actual_result

        self.assertSetEqual(actual_cidrs_to_add, expected_cidrs_to_add)
        self.assertSetEqual(actual_cidrs_to_delete, expected_cidrs_to_delete)

    def test__process_cidrs_when_current_namespace_contains_mix_cidrs(self):
        """Current namespace cidrs contains stale cidrs and it is missing
        new required cidrs.
        """
        current_namespace_cidrs = set([n_const.METADATA_CIDR,
                                      '10.0.1.0/31',
                                      '10.0.1.0/28'])
        datapath_port_ips = ['10.0.0.2', '10.0.1.5']
        metadaport_subnet_cidrs = ['10.0.0.0/30', '10.0.1.0/28', '11.0.1.2/24']

        expected_cidrs_to_add = set(['10.0.0.0/30'])
        expected_cidrs_to_delete = set(['10.0.1.0/31'])

        actual_result = self.agent._process_cidrs(current_namespace_cidrs,
                                                  datapath_port_ips,
                                                  metadaport_subnet_cidrs)
        actual_cidrs_to_add, actual_cidrs_to_delete = actual_result

        self.assertSetEqual(actual_cidrs_to_add, expected_cidrs_to_add)
        self.assertSetEqual(actual_cidrs_to_delete, expected_cidrs_to_delete)

    def test__get_provision_params_returns_none_when_metadata_port_is_missing(
            self):
        """Should return None when there is no metadata port in datapath and
        call teardown datapath.
        """
        network_id = '1'
        datapath = DatapathInfo(uuid='test123',
            external_ids={'name': 'neutron-{}'.format(network_id)})

        with mock.patch.object(
                self.agent.sb_idl, 'get_metadata_port_network',
                return_value=None),\
            mock.patch.object(
                self.agent, 'teardown_datapath') as tdp:
            self.assertIsNone(self.agent._get_provision_params(datapath))
            tdp.assert_called_once_with(datapath.uuid, network_id)

    def test__get_provision_params_returns_none_when_metadata_port_missing_mac(
            self):
        """Should return None when metadata port is missing MAC and
        call teardown datapath.
        """
        network_id = '1'
        datapath = DatapathInfo(uuid='test123',
            external_ids={'name': 'neutron-{}'.format(network_id)})
        metadadata_port = makePort(datapath,
                                   mac=['NO_MAC_HERE 1.2.3.4'],
                                   external_ids={'neutron:cidrs':
                                                 '10.204.0.10/29'})

        with mock.patch.object(
                self.agent.sb_idl, 'get_metadata_port_network',
                return_value=metadadata_port),\
            mock.patch.object(
                self.agent, 'teardown_datapath') as tdp:
            self.assertIsNone(self.agent._get_provision_params(datapath))
            tdp.assert_called_once_with(datapath.uuid, network_id)

    def test__get_provision_params_returns_none_when_no_vif_ports(self):
        """Should return None when there are no datapath ports with type
        "external" or ""(blank) and call teardown datapath.
        """
        network_id = '1'
        datapath = DatapathInfo(uuid='test123',
            external_ids={'name': 'neutron-{}'.format(network_id)})
        datapath_ports = [makePort(datapath, type='not_vif_type')]
        metadadata_port = makePort(datapath,
                                   mac=['fa:16:3e:22:65:18 1.2.3.4'],
                                   external_ids={'neutron:cidrs':
                                                 '10.204.0.10/29'})

        with mock.patch.object(self.agent.sb_idl, 'get_metadata_port_network',
                    return_value=metadadata_port),\
                mock.patch.object(self.agent.sb_idl, 'get_ports_on_chassis',
                    return_value=datapath_ports),\
                mock.patch.object(self.agent, 'teardown_datapath') as tdp:
            self.assertIsNone(self.agent._get_provision_params(datapath))
            tdp.assert_called_once_with(datapath.uuid, network_id)

    def test__get_provision_params_returns_provision_parameters(self):
        """The happy path when datapath has ports with "external" or ""(blank)
        types and metadata port contains MAC and subnet CIDRs.
        """
        network_id = '1'
        port_ip = '1.2.3.4'
        metada_port_mac = "fa:16:3e:22:65:18"
        metada_port_subnet_cidr = "10.204.0.10/29"
        metada_port_logical_port = "3b66c176-199b-48ec-8331-c1fd3f6e2b44"

        datapath = DatapathInfo(uuid='test123',
            external_ids={'name': 'neutron-{}'.format(network_id)})
        datapath_ports = [makePort(datapath,
                                   mac=['fa:16:3e:e7:ac {}'.format(port_ip)])]
        metadadata_port = makePort(datapath,
                                   mac=[
                                       '{} 10.204.0.1'.format(metada_port_mac)
                                   ],
                                   external_ids={'neutron:cidrs':
                                                 metada_port_subnet_cidr},
                                   logical_port=metada_port_logical_port)

        with mock.patch.object(self.agent.sb_idl, 'get_metadata_port_network',
                return_value=metadadata_port),\
            mock.patch.object(self.agent.sb_idl, 'get_ports_on_chassis',
                return_value=datapath_ports):
            actual_params = self.agent._get_provision_params(datapath)

        net_name, datapath_port_ips, metadata_port_info = actual_params

        self.assertEqual(network_id, net_name)
        self.assertListEqual([port_ip], datapath_port_ips)
        self.assertEqual(metada_port_mac, metadata_port_info.mac)
        self.assertSetEqual(set([metada_port_subnet_cidr]),
                            metadata_port_info.ip_addresses)
        self.assertEqual(metada_port_logical_port,
                         metadata_port_info.logical_port)

    def test_provision_datapath(self):
        """Test datapath provisioning.

        Check that the VETH pair, OVS port and namespace associated to this
        namespace are created, that the interface is properly configured with
        the right IP addresses and that the metadata proxy is spawned.
        """
        net_name = '123'
        metadaport_logical_port = '123-abc-456'
        datapath_ports_ips = ['10.0.0.1', '10.0.0.2']
        metada_port_info = agent.MetadataPortInfo(
            mac='aa:bb:cc:dd:ee:ff',
            ip_addresses=['10.0.0.1/23',
                          '2001:470:9:1224:5595:dd51:6ba2:e788/64'],
            logical_port=metadaport_logical_port
        )
        provision_params = (net_name, datapath_ports_ips, metada_port_info,)
        nemaspace_name = 'namespace'

        with mock.patch.object(self.agent,
                               '_get_provision_params',
                               return_value=provision_params),\
                mock.patch.object(
                    ip_lib, 'device_exists', return_value=False),\
                mock.patch.object(
                    ip_lib.IPDevice, 'exists', return_value=False),\
                mock.patch.object(agent.MetadataAgent, '_get_veth_name',
                                  return_value=['veth_0', 'veth_1']),\
                mock.patch.object(agent.MetadataAgent, '_get_namespace_name',
                                  return_value=nemaspace_name),\
                mock.patch.object(ip_link, 'set_up') as link_set_up,\
                mock.patch.object(ip_link, 'set_address') as link_set_addr,\
                mock.patch.object(ip_addr, 'list', return_value=[]),\
                mock.patch.object(ip_addr, 'add') as ip_addr_add,\
                mock.patch.object(
                    ip_wrap, 'add_veth',
                    return_value=[ip_lib.IPDevice('ip1'),
                                  ip_lib.IPDevice('ip2')]) as add_veth,\
                mock.patch.object(
                    driver.MetadataDriver,
                    'spawn_monitored_metadata_proxy') as spawn_mdp, \
                mock.patch.object(
                    self.agent, '_ensure_datapath_checksum') as mock_checksum:

            # Simulate that the VETH pair was already present in 'br-fake'.
            # We need to assert that it was deleted first.
            self.agent.ovs_idl.list_br.return_value.execute.return_value = (
                ['br-int', 'br-fake'])
            self.agent.provision_datapath('fake_datapath')

            # Check that the port was deleted from br-fake
            self.agent.ovs_idl.del_port.assert_called_once_with(
                'veth_0', bridge='br-fake', if_exists=True)
            # Check that the VETH pair is created
            add_veth.assert_called_once_with('veth_0', 'veth_1',
                nemaspace_name)
            # Make sure that the two ends of the VETH pair have been set as up.
            self.assertEqual(2, link_set_up.call_count)
            link_set_addr.assert_called_once_with('aa:bb:cc:dd:ee:ff')
            # Make sure that the port has been added to OVS.
            self.agent.ovs_idl.add_port.assert_called_once_with(
                'br-int', 'veth_0')
            self.agent.ovs_idl.db_set.assert_called_once_with(
                'Interface', 'veth_0',
                ('external_ids', {'iface-id': metadaport_logical_port}))
            # Check that the metadata port has the IP addresses properly
            # configured and that IPv6 address has been skipped.
            expected_calls = [mock.call('10.0.0.1/23'),
                              mock.call(n_const.METADATA_CIDR)]
            self.assertEqual(sorted(expected_calls),
                             sorted(ip_addr_add.call_args_list))
            # Check that metadata proxy has been spawned
            spawn_mdp.assert_called_once_with(
                mock.ANY, nemaspace_name, 80, mock.ANY,
                bind_address=n_const.METADATA_V4_IP, network_id=net_name)
            mock_checksum.assert_called_once_with(nemaspace_name)

    def test__load_config(self):
        # Chassis name UUID formatted string. OVN bridge "br-ovn".
        valid_uuid_str = uuidutils.generate_uuid()
        self.agent.ovs_idl.db_get.return_value.execute.side_effect = [
            {'system-id': valid_uuid_str}, {'ovn-bridge': 'br-ovn'}]
        self.agent._load_config()
        self.assertEqual(valid_uuid_str, self.agent.chassis)
        self.assertEqual(uuid.UUID(valid_uuid_str), self.agent.chassis_id)
        self.assertEqual('br-ovn', self.agent.ovn_bridge)

        # Chassis name non UUID formatted string. OVN bridge not defined,
        # "br-int" assigned by default.
        self.agent.ovs_idl.db_get.return_value.execute.side_effect = [
            {'system-id': 'RandomName1'}, {}]
        self.agent._load_config()
        generated_uuid = uuid.uuid5(agent.OVN_METADATA_UUID_NAMESPACE,
                                    'RandomName1')
        self.assertEqual('RandomName1', self.agent.chassis)
        self.assertEqual(generated_uuid, self.agent.chassis_id)
        self.assertEqual('br-int', self.agent.ovn_bridge)

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

from neutron_lib import constants as n_const
from oslo_config import cfg
from oslo_config import fixture as config_fixture

from neutron.agent.linux import ip_lib
from neutron.agent.linux.ip_lib import IpAddrCommand as ip_addr
from neutron.agent.linux.ip_lib import IpLinkCommand as ip_link
from neutron.agent.linux.ip_lib import IpNetnsCommand as ip_netns
from neutron.agent.linux.ip_lib import IPWrapper as ip_wrap
from neutron.agent.ovn.metadata import agent
from neutron.agent.ovn.metadata import driver
from neutron.conf.agent.metadata import config as meta_conf
from neutron.conf.agent.ovn.metadata import config as ovn_meta_conf
from neutron.tests import base


OvnPortInfo = collections.namedtuple(
    'OvnPortInfo', ['datapath', 'type', 'mac', 'external_ids', 'logical_port'])
DatapathInfo = collections.namedtuple('DatapathInfo', ['uuid', 'external_ids'])


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

    def test_sync(self):
        with mock.patch.object(
                self.agent, 'ensure_all_networks_provisioned') as enp,\
                mock.patch.object(
                    ip_lib, 'list_network_namespaces') as lnn,\
                mock.patch.object(
                    self.agent, 'teardown_datapath') as tdp:
            enp.return_value = ['ovnmeta-1', 'ovnmeta-2']
            lnn.return_value = ['ovnmeta-1', 'ovnmeta-2']

            self.agent.sync()

            enp.assert_called_once_with()
            lnn.assert_called_once_with()
            tdp.assert_not_called()

    def test_sync_teardown_namespace(self):
        """Test that sync tears down unneeded metadata namespaces."""
        with mock.patch.object(
                self.agent, 'ensure_all_networks_provisioned') as enp,\
                mock.patch.object(
                    ip_lib, 'list_network_namespaces') as lnn,\
                mock.patch.object(
                    self.agent, 'teardown_datapath') as tdp:
            enp.return_value = ['ovnmeta-1', 'ovnmeta-2']
            lnn.return_value = ['ovnmeta-1', 'ovnmeta-2', 'ovnmeta-3',
                                'ns1', 'ns2']

            self.agent.sync()

            enp.assert_called_once_with()
            lnn.assert_called_once_with()
            tdp.assert_called_once_with('3')

    def test_ensure_all_networks_provisioned(self):
        """Test networks are provisioned.

        This test simulates that this chassis has the following ports:
            * datapath '0': 1 port
            * datapath '1': 2 ports
            * datapath '2': 1 port
            * datapath '3': 1 port with type 'external'
            * datapath '5': 1 port with type 'unknown'

        It is expected that only datapaths '0', '1' and '2' are provisioned
        once.
        """

        ports = []
        for i in range(0, 3):
            ports.append(makePort(datapath=DatapathInfo(uuid=str(i),
                external_ids={'name': 'neutron-%d' % i})))
        ports.append(makePort(datapath=DatapathInfo(uuid='1',
            external_ids={'name': 'neutron-1'})))
        ports.append(makePort(datapath=DatapathInfo(uuid='3',
            external_ids={'name': 'neutron-3'}), type='external'))
        ports.append(makePort(datapath=DatapathInfo(uuid='5',
            external_ids={'name': 'neutron-5'}), type='unknown'))

        with mock.patch.object(self.agent, 'provision_datapath',
                               return_value=None) as pdp,\
                mock.patch.object(self.agent.sb_idl, 'get_ports_on_chassis',
                                  return_value=ports):
            self.agent.ensure_all_networks_provisioned()

            expected_calls = [mock.call(str(i), str(i)) for i in range(0, 4)]
            self.assertEqual(sorted(expected_calls),
                             sorted(pdp.call_args_list))

    def test_update_datapath_provision(self):
        ports = []
        for i in range(0, 3):
            ports.append(makePort(datapath=DatapathInfo(uuid=str(i),
                external_ids={'name': 'neutron-%d' % i})))
        ports.append(makePort(datapath=DatapathInfo(uuid='3',
            external_ids={'name': 'neutron-3'}), type='external'))

        with mock.patch.object(self.agent, 'provision_datapath',
                               return_value=None) as pdp,\
                mock.patch.object(self.agent, 'teardown_datapath') as tdp,\
                mock.patch.object(self.agent.sb_idl, 'get_ports_on_chassis',
                                  return_value=ports):
            self.agent.update_datapath('1', 'a')
            self.agent.update_datapath('3', 'b')
            expected_calls = [mock.call('1', 'a'), mock.call('3', 'b')]
            pdp.assert_has_calls(expected_calls)
            tdp.assert_not_called()

    def test_update_datapath_teardown(self):
        ports = []
        for i in range(0, 3):
            ports.append(makePort(datapath=DatapathInfo(uuid=str(i),
                external_ids={'name': 'neutron-%d' % i})))

        with mock.patch.object(self.agent, 'provision_datapath',
                               return_value=None) as pdp,\
                mock.patch.object(self.agent, 'teardown_datapath') as tdp,\
                mock.patch.object(self.agent.sb_idl, 'get_ports_on_chassis',
                                  return_value=ports):
            self.agent.update_datapath('5', 'a')
            tdp.assert_called_once_with('5', 'a')
            pdp.assert_not_called()

    def test_teardown_datapath(self):
        """Test teardown datapath.

        Check that the VETH pair, OVS port and namespace associated to this
        namespace are deleted and the metadata proxy is destroyed.
        """
        with mock.patch.object(self.agent,
                               'update_chassis_metadata_networks'),\
                mock.patch.object(
                    ip_netns, 'exists', return_value=True),\
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

    def test_provision_datapath(self):
        """Test datapath provisioning.

        Check that the VETH pair, OVS port and namespace associated to this
        namespace are created, that the interface is properly configured with
        the right IP addresses and that the metadata proxy is spawned.
        """

        metadata_port = makePort(mac=['aa:bb:cc:dd:ee:ff'],
                                 external_ids={
                                     'neutron:cidrs': '10.0.0.1/23 '
                                     '2001:470:9:1224:5595:dd51:6ba2:e788/64'},
                                 logical_port='port')

        with mock.patch.object(self.agent.sb_idl,
                               'get_metadata_port_network',
                               return_value=metadata_port),\
                mock.patch.object(
                    ip_lib, 'device_exists', return_value=False),\
                mock.patch.object(
                    ip_lib.IPDevice, 'exists', return_value=False),\
                mock.patch.object(agent.MetadataAgent, '_get_veth_name',
                                  return_value=['veth_0', 'veth_1']),\
                mock.patch.object(agent.MetadataAgent, '_get_namespace_name',
                                  return_value='namespace'),\
                mock.patch.object(ip_link, 'set_up') as link_set_up,\
                mock.patch.object(ip_link, 'set_address') as link_set_addr,\
                mock.patch.object(ip_addr, 'list', return_value=[]),\
                mock.patch.object(ip_addr, 'add') as ip_addr_add,\
                mock.patch.object(
                    ip_wrap, 'add_veth',
                    return_value=[ip_lib.IPDevice('ip1'),
                                  ip_lib.IPDevice('ip2')]) as add_veth,\
                mock.patch.object(
                    self.agent,
                    'update_chassis_metadata_networks') as update_chassis,\
                mock.patch.object(
                    driver.MetadataDriver,
                    'spawn_monitored_metadata_proxy') as spawn_mdp, \
                mock.patch.object(
                    self.agent, '_ensure_datapath_checksum') as mock_checksum:

            # Simulate that the VETH pair was already present in 'br-fake'.
            # We need to assert that it was deleted first.
            self.agent.ovs_idl.list_br.return_value.execute.return_value = (
                ['br-int', 'br-fake'])
            self.agent.provision_datapath('1', '1')

            # Check that the port was deleted from br-fake
            self.agent.ovs_idl.del_port.assert_called_once_with(
                'veth_0', bridge='br-fake', if_exists=True)
            # Check that the VETH pair is created
            add_veth.assert_called_once_with('veth_0', 'veth_1', 'namespace')
            # Make sure that the two ends of the VETH pair have been set as up.
            self.assertEqual(2, link_set_up.call_count)
            link_set_addr.assert_called_once_with('aa:bb:cc:dd:ee:ff')
            # Make sure that the port has been added to OVS.
            self.agent.ovs_idl.add_port.assert_called_once_with(
                'br-int', 'veth_0')
            self.agent.ovs_idl.db_set.assert_called_once_with(
                'Interface', 'veth_0', ('external_ids', {'iface-id': 'port'}))
            # Check that the metadata port has the IP addresses properly
            # configured and that IPv6 address has been skipped.
            expected_calls = [mock.call('10.0.0.1/23'),
                              mock.call(n_const.METADATA_CIDR)]
            self.assertEqual(sorted(expected_calls),
                             sorted(ip_addr_add.call_args_list))
            # Check that metadata proxy has been spawned
            spawn_mdp.assert_called_once_with(
                mock.ANY, 'namespace', 80, mock.ANY,
                bind_address=n_const.METADATA_V4_IP, network_id='1')
            # Check that the chassis has been updated with the datapath.
            update_chassis.assert_called_once_with('1')
            mock_checksum.assert_called_once_with('namespace')

    def _test_update_chassis_metadata_networks_helper(
            self, dp, remove, expected_dps, txn_called=True):
        current_dps = ['0', '1', '2']
        with mock.patch.object(self.agent.sb_idl,
                               'get_chassis_metadata_networks',
                               return_value=current_dps),\
                mock.patch.object(self.agent.sb_idl,
                                  'set_chassis_metadata_networks',
                                  retrurn_value=True),\
                mock.patch.object(self.agent.sb_idl,
                                  'create_transaction') as create_txn_mock:

            self.agent.update_chassis_metadata_networks(dp, remove=remove)
            updated_dps = self.agent.sb_idl.get_chassis_metadata_networks(
                self.agent.chassis)

            self.assertEqual(updated_dps, expected_dps)
            self.assertEqual(create_txn_mock.called, txn_called)

    def test_update_chassis_metadata_networks_add(self):
        dp = '4'
        remove = False
        expected_dps = ['0', '1', '2', '4']
        self._test_update_chassis_metadata_networks_helper(
            dp, remove, expected_dps)

    def test_update_chassis_metadata_networks_remove(self):
        dp = '2'
        remove = True
        expected_dps = ['0', '1']
        self._test_update_chassis_metadata_networks_helper(
            dp, remove, expected_dps)

    def test_update_chassis_metadata_networks_add_dp_exists(self):
        dp = '2'
        remove = False
        expected_dps = ['0', '1', '2']
        self._test_update_chassis_metadata_networks_helper(
            dp, remove, expected_dps, txn_called=False)

    def test_update_chassis_metadata_networks_remove_no_dp(self):
        dp = '3'
        remove = True
        expected_dps = ['0', '1', '2']
        self._test_update_chassis_metadata_networks_helper(
            dp, remove, expected_dps, txn_called=False)

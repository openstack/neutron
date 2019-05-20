# Copyright 2018 Ericsson
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

import functools

from neutron_lib import constants

from neutron.common import utils
from neutron.tests.common import net_helpers
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import config as f_const
from neutron.tests.fullstack.resources import environment
from neutron.tests.unit import testlib_api

load_tests = testlib_api.module_load_tests

BR_MAPPINGS = 'bridge_mappings'
DEV_MAPPINGS = 'device_mappings'


def _get_physnet_names_from_mapping(mapping):
    physnets = []
    for pair in mapping.split(','):
        physnets.append(pair.split(':')[0])
    return physnets


def _add_new_device_to_agent_config(l2_agent_config, mapping_key_name,
                                    new_dev):
    old_bw = l2_agent_config[constants.RP_BANDWIDTHS]
    old_mappings = l2_agent_config[mapping_key_name]
    if new_dev in old_bw or new_dev in old_mappings:
        return

    new_mappings = 'physnetnew:%s' % new_dev
    new_bw = '%s:%s:%s' % (new_dev,
                           f_const.MINIMUM_BANDWIDTH_EGRESS_KBPS,
                           f_const.MINIMUM_BANDWIDTH_INGRESS_KBPS)
    l2_agent_config[mapping_key_name] = '%s,%s' % (
        old_mappings, new_mappings)
    l2_agent_config[constants.RP_BANDWIDTHS] = '%s,%s' % (
        old_bw, new_bw)


def _change_agent_conf(l2_agent_config, l2_agent,
                       mapping_key_name, new_dev):
    _add_new_device_to_agent_config(l2_agent_config, mapping_key_name, new_dev)
    l2_agent.agent_cfg_fixture.write_config_to_configfile()


def _add_new_bridge_and_restart_agent(host):
    l2_agent = host.l2_agent
    l2_agent_config = l2_agent.agent_cfg_fixture.config

    if 'ovs' in host.agents:
        new_dev = utils.get_rand_device_name(prefix='br-new')
        _change_agent_conf(
            l2_agent_config['ovs'], l2_agent, BR_MAPPINGS, new_dev)
        physnets = _get_physnet_names_from_mapping(
            l2_agent_config['ovs'][BR_MAPPINGS])
        br_phys_new = host.useFixture(
            net_helpers.OVSBridgeFixture(new_dev)).bridge
        host.connect_to_central_network_via_vlans(br_phys_new)
    elif 'sriov' in host.agents:
        new_dev = utils.get_rand_device_name(prefix='ens7')
        _change_agent_conf(
            l2_agent_config['sriov_nic'], l2_agent,
            'physical_device_mappings', new_dev)
        physnets = _get_physnet_names_from_mapping(
            l2_agent_config['sriov_nic']['physical_device_mappings'])

    l2_agent.restart()
    return physnets


class TestAgentBandwidthReport(base.BaseFullStackTestCase):

    scenarios = [
        (constants.AGENT_TYPE_OVS,
         {'l2_agent_type': constants.AGENT_TYPE_OVS}),
        (constants.AGENT_TYPE_NIC_SWITCH,
         {'l2_agent_type': constants.AGENT_TYPE_NIC_SWITCH})
    ]

    def setUp(self, env=None):
        if not env:
            host_desc = [environment.HostDescription(
                l3_agent=False,
                l2_agent_type=self.l2_agent_type)]
            env_desc = environment.EnvironmentDescription(
                network_type='vlan',
                l2_pop=False,
                report_bandwidths=True,
            )
            env = environment.Environment(env_desc, host_desc)

        super(TestAgentBandwidthReport, self).setUp(env)

    def _check_agent_configurations(self, agent_id, expected_physnets):
        agent = self.client.show_agent(agent_id)['agent']
        agent_configurations = agent['configurations']
        if 'Open vSwitch' in agent['agent_type']:
            mapping_key = BR_MAPPINGS
        elif 'NIC Switch' in agent['agent_type']:
            mapping_key = DEV_MAPPINGS
        else:
            return False

        for physnet in expected_physnets:
            if physnet not in agent_configurations[mapping_key]:
                return False
            bridge_or_devices = agent_configurations[mapping_key][physnet]

            if (constants.RP_BANDWIDTHS not in agent_configurations or
                    constants.RP_INVENTORY_DEFAULTS not in
                    agent_configurations):
                return False

            if mapping_key == BR_MAPPINGS:
                if (bridge_or_devices not in
                        agent_configurations[constants.RP_BANDWIDTHS]):
                    return False
            else:
                for device in bridge_or_devices:
                    if (device not in
                            agent_configurations[constants.RP_BANDWIDTHS]):
                        return False

        for device in agent_configurations[constants.RP_BANDWIDTHS]:
            conf_device = agent_configurations[constants.RP_BANDWIDTHS][device]
            if (f_const.MINIMUM_BANDWIDTH_INGRESS_KBPS !=
                    conf_device['ingress'] and
                    f_const.MINIMUM_BANDWIDTH_EGRESS_KBPS !=
                    conf_device[device]['egress']):
                return False
        return True

    def test_agent_configurations(self):
        agents = self.client.list_agents()

        self.assertEqual(1, len(agents['agents']))
        self.assertTrue(agents['agents'][0]['alive'])

        agent_config = self.environment.hosts[0].l2_agent.agent_config
        if 'ovs' in self.environment.hosts[0].agents:
            physnets = _get_physnet_names_from_mapping(
                agent_config['ovs'][BR_MAPPINGS])
        elif 'sriov' in self.environment.hosts[0].agents:
            physnets = _get_physnet_names_from_mapping(
                agent_config['sriov_nic']['physical_device_mappings'])

        self.assertTrue(
            self._check_agent_configurations(agents['agents'][0]['id'],
                                             physnets))

        # Add new physnet with bandwidth value to agent config and check
        # if after agent restart and report_interval wait it is visible in
        # the configurations field.
        physnets = _add_new_bridge_and_restart_agent(self.environment.hosts[0])

        agents = self.client.list_agents()
        l2_agent = agents['agents'][0]
        neutron_config = self.environment.hosts[0].l2_agent.neutron_config
        report_interval = neutron_config['agent']['report_interval']

        check_agent_alive = functools.partial(self._check_agent_configurations,
                                              l2_agent['id'],
                                              physnets)
        utils.wait_until_true(
            predicate=check_agent_alive,
            timeout=float(report_interval) + 10,
            sleep=5)


class TestPlacementBandwidthReport(base.BaseFullStackTestCase):

    scenarios = [
        (constants.AGENT_TYPE_OVS,
         {'l2_agent_type': constants.AGENT_TYPE_OVS,
          'mech_drivers': 'openvswitch,linuxbridge',
          'placement_port': '8080'}),
        (constants.AGENT_TYPE_NIC_SWITCH,
         {'l2_agent_type': constants.AGENT_TYPE_NIC_SWITCH,
          'mech_drivers': 'sriovnicswitch',
          'placement_port': '8081'})
    ]

    def setUp(self):
        host_desc = [environment.HostDescription(
            l3_agent=False,
            l2_agent_type=self.l2_agent_type)]
        env_desc = environment.EnvironmentDescription(
            network_type='vlan',
            l2_pop=False,
            mech_drivers=self.mech_drivers,
            report_bandwidths=True,
            has_placement=True,
            placement_port=self.placement_port
        )
        env = environment.Environment(env_desc, host_desc)
        super(TestPlacementBandwidthReport, self).setUp(env)

    def _check_agent_not_synced(self):
        return not self._check_agent_synced()

    def _check_agent_synced(self):
        agents = self.client.list_agents()
        if (len(agents['agents']) == 1 and
                agents['agents'][0]['resources_synced']):
            return True
        return False

    def test_configurations_are_synced_towards_placement(self):
        neutron_config = self.environment.hosts[0].l2_agent.neutron_config
        report_interval = int(neutron_config['agent']['report_interval'])

        check_agent_synced = functools.partial(self._check_agent_synced)
        utils.wait_until_true(
            predicate=check_agent_synced,
            timeout=report_interval + 10,
            sleep=1)

        self.environment.placement.process_fixture.stop()
        _add_new_bridge_and_restart_agent(self.environment.hosts[0])

        check_agent_not_synced = functools.partial(
            self._check_agent_not_synced)
        utils.wait_until_true(
            predicate=check_agent_not_synced,
            timeout=report_interval + 10,
            sleep=1)

        self.environment.placement.process_fixture.start()
        check_agent_synced = functools.partial(self._check_agent_synced)
        utils.wait_until_true(
            predicate=check_agent_synced,
            timeout=report_interval + 10,
            sleep=1)

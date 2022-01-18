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
#

import random
from unittest import mock

from neutron.tests import base

from neutron.common.ovn import constants as ovn_const
from neutron.scheduler import l3_ovn_scheduler


class FakeOVNGatewaySchedulerNbOvnIdl(object):
    def __init__(self, chassis_gateway_mapping, gateway):
        self.get_all_chassis_gateway_bindings = mock.Mock(
            return_value=chassis_gateway_mapping['Chassis_Bindings'])
        self.get_gateway_chassis_binding = mock.Mock(
            return_value=chassis_gateway_mapping['Gateways'].get(gateway,
                                                                 None))


class FakeOVNGatewaySchedulerSbOvnIdl(object):
    def __init__(self, chassis_gateway_mapping):
        self.get_all_chassis = mock.Mock(
            return_value=chassis_gateway_mapping['Chassis'])


class TestOVNGatewayScheduler(base.BaseTestCase):

    def setUp(self):
        super(TestOVNGatewayScheduler, self).setUp()

        # Overwritten by derived classes
        self.l3_scheduler = None

        # Used for unit tests
        self.new_gateway_name = 'lrp_new'
        self.fake_chassis_gateway_mappings = {
            'None': {'Chassis': [],
                     'Gateways': {
                         'g1': [ovn_const.OVN_GATEWAY_INVALID_CHASSIS]}},
            'Multiple1': {'Chassis': ['hv1', 'hv2', 'hv3', 'hv4', 'hv5'],
                          'Gateways': {'g1': ['hv1', 'hv2', 'hv3', 'hv4'],
                                       'g2': ['hv1', 'hv2', 'hv3'],
                                       'g3': ['hv1', 'hv2'],
                                       'g4': ['hv1']}},
            'Multiple2': {'Chassis': ['hv1', 'hv2', 'hv3'],
                          'Gateways': {'g1': ['hv1'],
                                       'g2': ['hv1'],
                                       'g3': ['hv1']}},
            'Multiple3': {'Chassis': ['hv1', 'hv2', 'hv3'],
                          'Gateways': {'g1': ['hv3'],
                                       'g2': ['hv2'],
                                       'g3': ['hv2']}},
            'Multiple4': {'Chassis': ['hv1', 'hv2'],
                          'Gateways': {'g1': ['hv1'],
                                       'g2': ['hv1'],
                                       'g3': ['hv1'],
                                       'g4': ['hv1'],
                                       'g5': ['hv1'],
                                       'g6': ['hv1']}}}

        # Determine the chassis to gateway list bindings
        for details in self.fake_chassis_gateway_mappings.values():
            self.assertNotIn(self.new_gateway_name, details['Gateways'])
            details.setdefault('Chassis_Bindings', {})
            for chassis in details['Chassis']:
                details['Chassis_Bindings'].setdefault(chassis, [])
            for gw, chassis_list in details['Gateways'].items():
                for chassis in chassis_list:
                    if chassis in details['Chassis_Bindings']:
                        details['Chassis_Bindings'][chassis].append((gw, 0))

    def select(self, chassis_gateway_mapping, gateway_name):
        nb_idl = FakeOVNGatewaySchedulerNbOvnIdl(chassis_gateway_mapping,
                                                 gateway_name)
        sb_idl = FakeOVNGatewaySchedulerSbOvnIdl(chassis_gateway_mapping)
        return self.l3_scheduler.select(nb_idl, sb_idl,
                                        gateway_name)

    def filter_existing_chassis(self, *args, **kwargs):
        return self.l3_scheduler.filter_existing_chassis(
            nb_idl=kwargs.pop('nb_idl'), gw_chassis=kwargs.pop('gw_chassis'),
            physnet=kwargs.pop('physnet'),
            chassis_physnets=kwargs.pop('chassis_physnets'),
            existing_chassis=kwargs.pop('existing_chassis'),
            az_hints=kwargs.pop('az_hints', []),
            chassis_with_azs=kwargs.pop('chassis_with_azs', {}))


class OVNGatewayChanceScheduler(TestOVNGatewayScheduler):

    def setUp(self):
        super(OVNGatewayChanceScheduler, self).setUp()
        self.l3_scheduler = l3_ovn_scheduler.OVNGatewayChanceScheduler()

    def test_no_chassis_available_for_existing_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['None']
        gateway_name = random.choice(list(mapping['Gateways'].keys()))
        chassis = self.select(mapping, gateway_name)
        self.assertEqual([ovn_const.OVN_GATEWAY_INVALID_CHASSIS], chassis)

    def test_no_chassis_available_for_new_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['None']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name)
        self.assertEqual([ovn_const.OVN_GATEWAY_INVALID_CHASSIS], chassis)

    def test_random_chassis_available_for_new_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple1']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name)
        self.assertCountEqual(chassis, mapping.get('Chassis'))

    def test_filter_existing_chassis(self):
        # filter_existing_chassis is scheduler independent, but calling
        # it from Base class didnt seem right. Also, there is no need to have
        # another test in LeastLoadedScheduler.
        chassis_physnets = {'temp': ['phys-network-0', 'phys-network-1']}
        nb_idl = FakeOVNGatewaySchedulerNbOvnIdl(
            self.fake_chassis_gateway_mappings['None'], 'g1')
        # Check if invalid chassis is removed
        self.assertEqual(
            ['temp'], self.filter_existing_chassis(
                nb_idl=nb_idl, gw_chassis=["temp"],
                physnet='phys-network-1',
                chassis_physnets=chassis_physnets,
                existing_chassis=['temp',
                                  ovn_const.OVN_GATEWAY_INVALID_CHASSIS]))
        # Check if invalid is removed -II
        self.assertFalse(
            self.filter_existing_chassis(
                nb_idl=nb_idl, gw_chassis=["temp"],
                physnet='phys-network-1',
                chassis_physnets=chassis_physnets,
                existing_chassis=[ovn_const.OVN_GATEWAY_INVALID_CHASSIS]))
        # Check if chassis removed when physnet doesnt exist
        self.assertFalse(
            self.filter_existing_chassis(
                nb_idl=nb_idl, gw_chassis=["temp"],
                physnet='phys-network-2',
                chassis_physnets=chassis_physnets,
                existing_chassis=['temp']))
        # Check if chassis removed when it doesnt exist in gw_chassis
        # or in chassis_physnets
        self.assertFalse(
            self.filter_existing_chassis(
                nb_idl=nb_idl, gw_chassis=["temp1"],
                physnet='phys-network-2',
                chassis_physnets=chassis_physnets,
                existing_chassis=['temp']))


class OVNGatewayLeastLoadedScheduler(TestOVNGatewayScheduler):

    def setUp(self):
        super(OVNGatewayLeastLoadedScheduler, self).setUp()
        self.l3_scheduler = l3_ovn_scheduler.OVNGatewayLeastLoadedScheduler()

    def test_no_chassis_available_for_existing_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['None']
        gateway_name = random.choice(list(mapping['Gateways'].keys()))
        chassis = self.select(mapping, gateway_name)
        self.assertEqual([ovn_const.OVN_GATEWAY_INVALID_CHASSIS], chassis)

    def test_no_chassis_available_for_new_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['None']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name)
        self.assertEqual([ovn_const.OVN_GATEWAY_INVALID_CHASSIS], chassis)

    def test_least_loaded_chassis_available_for_new_gateway1(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple1']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name)
        self.assertCountEqual(chassis, mapping.get('Chassis'))
        # least loaded will be the first one in the list,
        # networking-ovn will assign highest priority to this first element
        self.assertEqual(['hv5', 'hv4', 'hv3', 'hv2', 'hv1'], chassis)

    def test_least_loaded_chassis_available_for_new_gateway2(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple2']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name)
        # hv1 will have least priority
        self.assertEqual(chassis[2], 'hv1')

    def test_least_loaded_chassis_available_for_new_gateway3(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple3']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name)
        # least loaded chassis will be in the front of the list
        self.assertEqual(['hv1', 'hv3', 'hv2'], chassis)

    def test_least_loaded_chassis_with_rebalance(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple4']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name)
        # least loaded chassis will be in the front of the list
        self.assertEqual(['hv2', 'hv1'], chassis)

    def test_existing_chassis_available_for_existing_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple1']
        gateway_name = random.choice(list(mapping['Gateways'].keys()))
        chassis = self.select(mapping, gateway_name)
        self.assertEqual(ovn_const.MAX_GW_CHASSIS, len(chassis))

    def test__get_chassis_load_by_prios_several_ports(self):
        # Adding 5 ports of prio 1 and 5 ports of prio 2
        chassis_info = []
        for i in range(1, 6):
            chassis_info.append(('lrp', 1))
            chassis_info.append(('lrp', 2))
        actual = self.l3_scheduler._get_chassis_load_by_prios(chassis_info)
        expected = {1: 5, 2: 5}
        self.assertCountEqual(expected.items(), actual)

    def test__get_chassis_load_by_prios_no_ports(self):
        self.assertFalse(self.l3_scheduler._get_chassis_load_by_prios([]))

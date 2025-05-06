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


class FakeOVNGatewaySchedulerNbOvnIdl:
    def __init__(self, chassis_gateway_mapping, gateway):
        self.get_all_chassis_gateway_bindings = mock.Mock(
            return_value=chassis_gateway_mapping['Chassis_Bindings'])
        self.get_gateway_chassis_binding = mock.Mock(
            return_value=chassis_gateway_mapping['Gateways'].get(gateway,
                                                                 None))
        self.get_lrouter_by_lrouter_port = mock.Mock(
            return_value=None)


class FakeOVNGatewaySchedulerSbOvnIdl:
    def __init__(self, chassis_and_azs):
        self.get_chassis_and_azs = mock.Mock(return_value=chassis_and_azs)


class TestOVNGatewayScheduler(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.mock_log = mock.patch.object(l3_ovn_scheduler, 'LOG').start()

        # Overwritten by derived classes
        self.l3_scheduler = None

        # Used for unit tests
        self.new_gateway_name = 'lrp_new'
        self.fake_chassis_gateway_mappings = {
            'None': {'Chassis': [],
                     'Gateways': {'g1': None}},
            'Multiple1': {'Chassis': ['hv1', 'hv2', 'hv3', 'hv4', 'hv5'],
                          'Gateways': {
                              'g1': ['hv1', 'hv2', 'hv4', 'hv3', 'hv5'],
                              'g2': ['hv2', 'hv3', 'hv5', 'hv1', 'hv4'],
                              'g3': ['hv3', 'hv5', 'hv1', 'hv4', 'hv2'],
                              'g4': ['hv4', 'hv1', 'hv2', 'hv5', 'hv3']}},
            'Multiple2': {'Chassis': ['hv1', 'hv2', 'hv3'],
                          'Gateways': {'g1': ['hv1', 'hv2', 'hv3'],
                                       'g2': ['hv2', 'hv1', 'hv3'],
                                       'g3': ['hv2', 'hv1', 'hv3']}},
            'Multiple3': {'Chassis': ['hv1', 'hv2', 'hv3'],
                          'Gateways': {'g1': ['hv3', 'hv2', 'hv1'],
                                       'g2': ['hv2', 'hv1', 'hv3'],
                                       'g3': ['hv2', 'hv1', 'hv3']}},
            'Multiple4': {'Chassis': ['hv1', 'hv2'],
                          'Gateways': {'g1': ['hv1', 'hv2'],
                                       'g2': ['hv1'],
                                       'g3': ['hv1'],
                                       'g4': ['hv1'],
                                       'g5': ['hv1'],
                                       'g6': ['hv1']}},
            'Multiple5': {'Chassis': ['hv1', 'hv2', 'hv3', 'hv4', 'hv5'],
                          'Gateways': {
                              'g1': ['hv1', 'hv2', 'hv3', 'hv4', 'hv5'],
                              'g2': ['hv3', 'hv2', 'hv4', 'hv5', 'hv1'],
                              'g3': ['hv4', 'hv5', 'hv1', 'hv2', 'hv3'],
                              'g4': ['hv5', 'hv1', 'hv2', 'hv3', 'hv4']}},
            'Multiple6': {'Chassis': ['hv1', 'hv2', 'hv3'],
                          'Gateways': {
                              'g1': ['hv1', 'hv2', 'hv3'],
                              'g2': ['hv1', 'hv2', 'hv3'],
                              'g3': ['hv3', 'hv2', 'hv1'],
                              'g4': ['hv3', 'hv2', 'hv1']}}}

        self.fake_chassis_and_azs = {
            'None': {},
            'Multiple1': {},
            'Multiple2': {},
            'Multiple3': {},
            'Multiple4': {},
            'Multiple5': {},
            'Multiple6': {}}

        # Determine the chassis to gateway list bindings
        for details in self.fake_chassis_gateway_mappings.values():
            self.assertNotIn(self.new_gateway_name, details['Gateways'])
            details.setdefault('Chassis_Bindings', {})
            for chassis in details['Chassis']:
                details['Chassis_Bindings'].setdefault(chassis, [])
            for gw, chassis_list in details['Gateways'].items():
                chassis_list = chassis_list or []
                max_prio = len(chassis_list)
                for idx, chassis in enumerate(chassis_list):
                    prio = max_prio - idx
                    if chassis in details['Chassis_Bindings']:
                        details['Chassis_Bindings'][chassis].append((gw, prio))

    def select(self, chassis_gateway_mapping, gateway_name,
               chassis_and_azs, candidates=None):
        nb_idl = FakeOVNGatewaySchedulerNbOvnIdl(chassis_gateway_mapping,
                                                 gateway_name)
        sb_idl = FakeOVNGatewaySchedulerSbOvnIdl(chassis_and_azs)
        return self.l3_scheduler.select(nb_idl, sb_idl, gateway_name,
                                        candidates=candidates)

    def filter_existing_chassis(self, *args, **kwargs):
        return self.l3_scheduler.filter_existing_chassis(
            gw_chassis=kwargs.pop('gw_chassis'), physnet=kwargs.pop('physnet'),
            chassis_physnets=kwargs.pop('chassis_physnets'),
            existing_chassis=kwargs.pop('existing_chassis'),
            az_hints=kwargs.pop('az_hints', []),
            chassis_with_azs=kwargs.pop('chassis_with_azs', {}))


class OVNGatewayChanceScheduler(TestOVNGatewayScheduler):

    def setUp(self):
        super().setUp()
        self.l3_scheduler = l3_ovn_scheduler.OVNGatewayChanceScheduler()

    def test_no_chassis_available_for_existing_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['None']
        chassis_and_azs = self.fake_chassis_and_azs['None']
        gateway_name = random.choice(list(mapping['Gateways'].keys()))
        chassis = self.select(mapping, gateway_name, chassis_and_azs,
                              candidates=mapping['Chassis'])
        self.assertIsNone(chassis)

    def test_no_chassis_available_for_new_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['None']
        chassis_and_azs = self.fake_chassis_and_azs['None']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name, chassis_and_azs,
                              candidates=mapping['Chassis'])
        self.assertIsNone(chassis)

    def test_random_chassis_available_for_new_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple1']
        chassis_and_azs = self.fake_chassis_and_azs['Multiple1']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name, chassis_and_azs,
                              candidates=mapping['Chassis'])
        self.assertCountEqual(chassis, mapping.get('Chassis'))

    def test_no_candidates_provided(self):
        mapping = self.fake_chassis_gateway_mappings['None']
        chassis_and_azs = self.fake_chassis_and_azs['None']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name, chassis_and_azs)
        self.assertIsNone(chassis)
        self.mock_log.warning.assert_called_once_with(
            'Gateway %s was not scheduled on any chassis, no candidates are '
            'available', gateway_name)

    def test_filter_existing_chassis(self):
        # filter_existing_chassis is scheduler independent, but calling
        # it from Base class didnt seem right. Also, there is no need to have
        # another test in LeastLoadedScheduler.
        chassis_physnets = {'temp': ['phys-network-0', 'phys-network-1']}
        # Check if invalid chassis is removed
        self.assertEqual(
            ['temp'], self.filter_existing_chassis(
                gw_chassis=["temp"],
                physnet='phys-network-1',
                chassis_physnets=chassis_physnets,
                existing_chassis=['temp', None]))
        # Check if invalid is removed -II
        self.assertFalse(
            self.filter_existing_chassis(
                gw_chassis=["temp"],
                physnet='phys-network-1',
                chassis_physnets=chassis_physnets,
                existing_chassis=None))
        # Check if chassis removed when physnet doesnt exist
        self.assertFalse(
            self.filter_existing_chassis(
                gw_chassis=["temp"],
                physnet='phys-network-2',
                chassis_physnets=chassis_physnets,
                existing_chassis=['temp']))
        # Check if chassis removed when it doesnt exist in gw_chassis
        # or in chassis_physnets
        self.assertFalse(
            self.filter_existing_chassis(
                gw_chassis=["temp1"],
                physnet='phys-network-2',
                chassis_physnets=chassis_physnets,
                existing_chassis=['temp']))


class OVNGatewayChanceSchedulerWithAZ(OVNGatewayChanceScheduler):

    def setUp(self):
        super().setUp()

        self.fake_chassis_and_azs = {
            'None': {},
            'Multiple1': {'hv1': {'az-1'},
                          'hv2': {'az-0'},
                          'hv3': {'az-0'},
                          'hv4': {'az-0'},
                          'hv5': {'az-0'}},
            'Multiple2': {},
            'Multiple3': {},
            'Multiple4': {},
            'Multiple5': {},
            'Multiple6': {}}


class OVNGatewayLeastLoadedScheduler(TestOVNGatewayScheduler):

    def setUp(self):
        super().setUp()
        self.l3_scheduler = l3_ovn_scheduler.OVNGatewayLeastLoadedScheduler()

    def test_no_chassis_available_for_existing_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['None']
        chassis_and_azs = self.fake_chassis_and_azs['None']
        gateway_name = random.choice(list(mapping['Gateways'].keys()))
        chassis = self.select(mapping, gateway_name, chassis_and_azs,
                              candidates=mapping['Chassis'])
        self.assertIsNone(chassis)

    def test_no_chassis_available_for_new_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['None']
        chassis_and_azs = self.fake_chassis_and_azs['None']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name, chassis_and_azs,
                              candidates=mapping['Chassis'])
        self.assertIsNone(chassis)

    def test_least_loaded_chassis_available_for_new_gateway1(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple1']
        chassis_and_azs = self.fake_chassis_and_azs['Multiple1']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name, chassis_and_azs,
                              candidates=mapping['Chassis'])
        self.assertCountEqual(chassis, mapping.get('Chassis'))
        # least loaded will be the first one in the list,
        # networking-ovn will assign highest priority to this first element
        self.assertEqual(['hv5', 'hv4', 'hv3', 'hv2', 'hv1'], chassis)

    def test_least_loaded_chassis_available_for_new_gateway2(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple2']
        chassis_and_azs = self.fake_chassis_and_azs['Multiple2']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name, chassis_and_azs,
                              candidates=mapping['Chassis'])
        # hv1 will have least priority
        self.assertEqual(chassis[2], 'hv1')

    def test_least_loaded_chassis_available_for_new_gateway3(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple3']
        chassis_and_azs = self.fake_chassis_and_azs['Multiple3']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name, chassis_and_azs,
                              candidates=mapping['Chassis'])
        # least loaded chassis will be in the front of the list
        self.assertEqual(['hv1', 'hv3', 'hv2'], chassis)

    def test_least_loaded_chassis_with_rebalance(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple4']
        chassis_and_azs = self.fake_chassis_and_azs['Multiple4']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name, chassis_and_azs,
                              candidates=mapping['Chassis'])
        # least loaded chassis will be in the front of the list
        self.assertEqual(['hv2', 'hv1'], chassis)

    def test_least_loaded_chassis_per_priority(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple5']
        chassis_and_azs = self.fake_chassis_and_azs['Multiple5']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name, chassis_and_azs,
                              candidates=mapping['Chassis'])
        # we should now have the following hv's per priority:
        # p5: hv2 (since it currently does not have p5 ports)
        # p4: hv3 or hv4 (since both currently do not have p4 ports)
        # p3: hv5 (since it currently does not have p3 ports)
        # p2: hv1 (since it currently does not have p2 ports)
        # p1: hv3 or hv4 (since they only have one p1 port;
        #                 cant be hv2 since it was already selected)
        self.assertEqual(chassis[0], 'hv2')
        self.assertIn(chassis[1], ['hv3', 'hv4'])
        self.assertEqual(chassis[2], 'hv5')
        self.assertEqual(chassis[3], 'hv1')
        self.assertIn(chassis[4], ['hv3', 'hv4'])
        self.assertNotEqual(chassis[1], chassis[4])

    def test_least_loaded_chassis_per_priority2(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple6']
        chassis_and_azs = self.fake_chassis_and_azs['Multiple6']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name, chassis_and_azs,
                              candidates=mapping['Chassis'])
        # we should now have the following hv's per priority:
        # p3: hv2 (since it currently does not have p3 ports)
        # p2: hv1 or hv3 (since both currently do not have p2 ports)
        # p1: hv1 or hv3 (since they only have two p1 ports;
        #                 cant be hv2 since it was already selected)
        self.assertEqual(chassis[0], 'hv2')
        self.assertIn(chassis[1], ['hv1', 'hv3'])
        self.assertIn(chassis[2], ['hv1', 'hv3'])
        self.assertNotEqual(chassis[1], chassis[2])

    def test_existing_chassis_available_for_existing_gateway(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple1']
        chassis_and_azs = self.fake_chassis_and_azs['Multiple1']
        gateway_name = random.choice(list(mapping['Gateways'].keys()))
        chassis = self.select(mapping, gateway_name, chassis_and_azs,
                              candidates=mapping['Chassis'])
        self.assertEqual(ovn_const.MAX_GW_CHASSIS, len(chassis))


class OVNGatewayLeastLoadedSchedulerWithAZ(OVNGatewayLeastLoadedScheduler):

    def setUp(self):
        super().setUp()

        self.fake_chassis_and_azs = {
            'None': {},
            'Multiple1': {'hv1': {'az-0'},
                          'hv2': {'az-0'},
                          'hv3': {'az-1', 'az-3'},
                          'hv4': {'az-2'},
                          'hv5': {'az-1', 'az-2'}},
            'Multiple2': {},
            'Multiple3': {},
            'Multiple4': {},
            'Multiple5': {},
            'Multiple6': {}}

    def test_least_loaded_chassis_available_for_new_gateway1(self):
        mapping = self.fake_chassis_gateway_mappings['Multiple1']
        chassis_and_azs = self.fake_chassis_and_azs['Multiple1']
        gateway_name = self.new_gateway_name
        chassis = self.select(mapping, gateway_name, chassis_and_azs,
                              candidates=mapping['Chassis'])
        self.assertCountEqual(chassis, mapping.get('Chassis'))
        # least loaded will be the first one in the list,
        # networking-ovn will assign highest priority to this first element
        #
        # Order of chassis is now changed to take care of spreading over AZs :
        # hv5 is in az-1 and az-2 so it can stay first (priority order)
        # hv4 is in az-2, already in hv5 so it goes to the remaining
        # hv3 is in az-1, already in hv5 but az-3 is not, so hv3 is the next
        # one
        # hv2 is in az-0 which is new, so it's the next
        # After, hv4 and hv1 are remaining ones, stay in original order.
        self.assertEqual(['hv5', 'hv3', 'hv2', 'hv4', 'hv1'], chassis)

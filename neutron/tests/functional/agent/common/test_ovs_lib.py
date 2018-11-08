# Copyright (c) 2018 Red Hat, Inc.
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

import mock
from neutron_lib.services.qos import constants as qos_constants
from oslo_utils import uuidutils
import six

from neutron.agent.common import ovs_lib
from neutron.agent.linux import ip_lib
from neutron.plugins.ml2.drivers.openvswitch.agent.common \
    import constants as ovs_constants
from neutron.tests.functional import base


class BaseOVSTestCase(base.BaseSudoTestCase):

    def setUp(self):
        super(BaseOVSTestCase, self).setUp()
        self.br_name = ('br-' + uuidutils.generate_uuid())[:10]
        self.port_id = ('port-' + uuidutils.generate_uuid())[:8]
        self.ovs = ovs_lib.OVSBridge(self.br_name)
        self.elements_to_clean = {'bridges': [], 'devices': [],
                                  'qoses': [], 'queues': []}
        self.addCleanup(self._clean_system)

    def _clean_system(self):
        # NOTE(ralonsoh): the deletion order is important. First we need to
        # delete any bridge (and the ports attached); then the physical devices
        # created. QoS registers can be deleted if no port has those rules
        # assigned. Queues registers can be deleted if no QoS register refers
        # to those Queues.
        for bridge in self.elements_to_clean['bridges']:
            self.ovs.ovsdb.del_br(bridge).execute()
        for device in self.elements_to_clean['devices']:
            ip_lib.IPDevice(device).link.delete()
        for qos in self.elements_to_clean['qoses']:
            self.ovs.ovsdb.db_destroy('QoS', qos).execute()
        for queue in self.elements_to_clean['queues']:
            self.ovs.ovsdb.db_destroy('Queue', queue).execute()

    def _list_queues(self, queue_id=None):
        queues = self.ovs.ovsdb.db_list(
            'Queue',
            columns=('_uuid', 'other_config', 'external_ids')).execute()
        if queue_id:
            for queue in (queue for queue in queues
                          if queue['_uuid'] == queue_id):
                return queue
            else:
                return None
        return queues

    def _create_queue(self, max_kbps=3000, max_burst_kbps=2000, min_kbps=1000,
                      neutron_port_id=None, queue_num=None):
        neutron_port_id = (('port-' + uuidutils.generate_uuid())[:13]
                           if not neutron_port_id else neutron_port_id)
        queue_num = 'queue_num' if not queue_num else queue_num
        queue_id = self.ovs._update_queue(neutron_port_id, queue_num,
                                          max_kbps=max_kbps,
                                          max_burst_kbps=max_burst_kbps,
                                          min_kbps=min_kbps)

        self.elements_to_clean['queues'].append(queue_id)
        return queue_id, neutron_port_id

    def _create_qos(self, qos_id=None, queues=None):
        qos_id = self.ovs._update_qos(qos_id=qos_id, queues=queues)
        self.elements_to_clean['qoses'].append(qos_id)
        return qos_id

    def _list_qos(self, qos_id=None):
        qoses = self.ovs.ovsdb.db_list(
            'QoS',
            columns=('_uuid', 'queues', 'external_ids', 'type')).execute()
        if qos_id:
            for qos in (qos for qos in qoses if qos['_uuid'] == qos_id):
                return qos
            else:
                return None
        return qoses

    def _create_bridge(self):
        self.ovs.ovsdb.add_br(self.br_name).execute()
        self.elements_to_clean['bridges'].append(self.br_name)

    def _create_port(self, port_name):
        self.ovs.ovsdb.add_port(self.br_name, port_name).execute()

    def _find_port_uuid(self, port_name):
        return self.ovs.ovsdb.db_get('Port', port_name, '_uuid').execute()

    def _find_port_qos(self, port_name):
        return self.ovs.ovsdb.db_get('Port', port_name, 'qos').execute()

    def _create_dummy_device(self):
        device_name = ('dummy-' + uuidutils.generate_uuid())[:12]
        ip_lib.IPWrapper().add_dummy(device_name)
        self.elements_to_clean['devices'].append(device_name)
        return device_name

    def test__update_queue_new(self):
        queue_id, neutron_port_id = self._create_queue()
        self.assertIsNotNone(queue_id)
        other_config = {six.u('max-rate'): six.u('3000000'),
                        six.u('burst'): six.u('2000000'),
                        six.u('min-rate'): six.u('1000000')}
        external_ids = {six.u('port'): six.u(neutron_port_id),
                        six.u('queue-num'): six.u('queue_num'),
                        six.u('type'):
                            six.u(qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH)}

        queue = self._list_queues(queue_id)
        self.assertIsNotNone(queue)
        self.assertEqual(queue['_uuid'], queue_id)
        self.assertEqual(other_config, queue['other_config'])
        self.assertEqual(external_ids, queue['external_ids'])

    def test__update_queue_update(self):
        queue_id, neutron_port_id = self._create_queue()
        self.assertIsNotNone(queue_id)
        other_config = {six.u('max-rate'): six.u('6000000'),
                        six.u('burst'): six.u('5000000'),
                        six.u('min-rate'): six.u('4000000')}
        external_ids = {six.u('port'): six.u(neutron_port_id),
                        six.u('queue-num'): six.u('queue_num'),
                        six.u('type'):
                            six.u(qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH)}
        queue = self._list_queues(queue_id)
        self.assertIsNotNone(queue)

        queue_id, _ = self._create_queue(max_kbps=6000, max_burst_kbps=5000,
                                         min_kbps=4000, queue_num=queue_id,
                                         neutron_port_id=neutron_port_id)
        self.assertIsNotNone(queue_id)
        queue = self._list_queues(queue_id)
        self.assertEqual(queue['_uuid'], queue_id)
        self.assertEqual(other_config, queue['other_config'])
        self.assertEqual(external_ids, queue['external_ids'])

    def test__find_queue(self):
        queue_id, neutron_port_id = self._create_queue()
        queue_found = self.ovs._find_queue(neutron_port_id)
        self.assertEqual(queue_id, queue_found['_uuid'])

    def test__list_queues(self):
        ports = []
        queue_ids = []
        for _ in range(5):
            queue_id, neutron_port_id = self._create_queue()
            queue_ids.append(queue_id)
            ports.append(neutron_port_id)

        for idx, port in enumerate(ports):
            queue_list = self.ovs._list_queues(
                port=port, _type=qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH)
            self.assertEqual(1, len(queue_list))
            self.assertEqual(queue_ids[idx], queue_list[0]['_uuid'])
            self.assertEqual(port, queue_list[0]['external_ids']['port'])

            queue_list = self.ovs._list_queues(port=port, _type='other_type')
            self.assertEqual(0, len(queue_list))

    def test__delete_queue(self):
        queue_id, _ = self._create_queue()
        self.assertIsNotNone(self._list_queues(queue_id=queue_id))

        self.ovs._delete_queue(queue_id)
        self.assertIsNone(self._list_queues(queue_id=queue_id))

    def test__update_qos_new(self):
        queue_id, _ = self._create_queue()
        queues = {1: queue_id}

        qos_id = self._create_qos(queues=queues)
        qos = self._list_qos(qos_id)
        self.assertEqual(qos_id, qos['_uuid'])
        self.assertEqual(queues[1], qos['queues'][1].uuid)

    def test__update_qos_update(self):
        queue_id_1, _ = self._create_queue()
        queues = {1: queue_id_1}

        qos_id = self._create_qos(queues=queues)
        qos = self._list_qos(qos_id)
        self.assertEqual(qos_id, qos['_uuid'])
        self.assertEqual(1, len(qos['queues']))
        self.assertEqual(queues[1], qos['queues'][1].uuid)

        queue_id_2, _ = self._create_queue()
        queues[2] = queue_id_2

        self._create_qos(qos_id=qos_id, queues=queues)
        qos = self._list_qos(qos_id)
        self.assertEqual(qos_id, qos['_uuid'])
        self.assertEqual(2, len(qos['queues']))
        self.assertEqual(queues[1], qos['queues'][1].uuid)
        self.assertEqual(queues[2], qos['queues'][2].uuid)

    def test__find_qos(self):
        queue_id, _ = self._create_queue()
        queues = {1: queue_id}
        qos_id = self._create_qos()
        qos_ret, qos_queues = self.ovs._find_qos()
        self.assertEqual(qos_id, qos_ret)
        self.assertEqual(queues[1], queues[1])

    def test__set_port_qos(self):
        port_name = 'test_port'
        self._create_bridge()
        self._create_port(port_name)
        port_qos = self._find_port_qos(port_name)
        self.assertEqual([], port_qos)

        qos_id = self._create_qos()
        self.ovs._set_port_qos(port_name, qos_id=qos_id)
        port_qos = self._find_port_qos(port_name)
        self.assertEqual(qos_id, port_qos)

        self.ovs._set_port_qos(port_name)
        port_qos = self._find_port_qos(port_name)
        self.assertEqual([], port_qos)

    def test_get_bridge_ports(self):
        self._create_bridge()
        device_names = []
        for _ in range(5):
            device_name = self._create_dummy_device()
            device_names.append(device_name)
            self._create_port(device_name)

        bridge_ports = self.ovs.get_bridge_ports('')
        device_names.sort()
        bridge_ports.sort()
        self.assertEqual(device_names, bridge_ports)

    def test__set_queue_for_minimum_bandwidth(self):
        self._create_bridge()
        self.ovs._set_queue_for_minimum_bandwidth(1234)
        flows = self.ovs.dump_flows_for_table(ovs_constants.LOCAL_SWITCHING)
        expected = 'priority=200,reg4=0,in_port=1234 actions=set_queue:1234,' \
                   'load:0x1->NXM_NX_REG4[0],resubmit(,0)'
        self.assertIn(expected, flows)

    def test__unset_queue_for_minimum_bandwidth(self):
        self.test__set_queue_for_minimum_bandwidth()

        self.ovs._unset_queue_for_minimum_bandwidth(1234)
        flows = self.ovs.dump_flows_for_table(ovs_constants.LOCAL_SWITCHING)
        expected = 'in_port=1234'
        self.assertNotIn(expected, flows)

    def test_update_minimum_bandwidth_queue(self):
        port_name = 'test_output_port_1'
        self._create_bridge()
        self._create_port(port_name)
        queue_num = 1
        queue_id, _ = self._create_queue(neutron_port_id=self.port_id)
        queues = {queue_num: queue_id}
        qos_id = self._create_qos(queues=queues)

        self.ovs.update_minimum_bandwidth_queue(self.port_id, [port_name],
                                                queue_num, 1800)
        port_qos = self._find_port_qos(port_name)
        self.assertEqual(qos_id, port_qos)
        queue = self._list_queues(queue_id)
        self.assertEqual(six.u('1800000'), queue['other_config']['min-rate'])

    def test_update_minimum_bandwidth_queue_no_qos_no_queue(self):
        port_name = 'test_output_port_2'
        self._create_bridge()
        self._create_port(port_name)
        queue_num = 1

        self.ovs.update_minimum_bandwidth_queue(self.port_id, [port_name],
                                                queue_num, 1700)
        qos_id = self._find_port_qos(port_name)
        qos = self._list_qos(qos_id)
        queue_id = qos['queues'][1].uuid
        queue = self._list_queues(queue_id)
        self.elements_to_clean['qoses'].append(qos_id)
        self.elements_to_clean['queues'].append(queue_id)
        self.assertEqual(six.u('1700000'), queue['other_config']['min-rate'])

    def test_delete_minimum_bandwidth_queue(self):
        queue_id_1, neutron_port_id_1 = self._create_queue(queue_num=1)
        queue_id_2, neutron_port_id_2 = self._create_queue(queue_num=2)
        queues = {1: queue_id_1, 2: queue_id_2}
        qos_id = self._create_qos(queues=queues)
        qos = self._list_qos(qos_id)
        self.assertEqual(queue_id_1, qos['queues'][1].uuid)
        self.assertEqual(queue_id_2, qos['queues'][2].uuid)

        self.ovs.delete_minimum_bandwidth_queue(neutron_port_id_2)
        qos = self._list_qos(qos_id)
        self.assertEqual(1, len(qos['queues']))
        self.assertEqual(queue_id_1, qos['queues'][1].uuid)

        self.ovs.delete_minimum_bandwidth_queue(neutron_port_id_1)
        qos = self._list_qos(qos_id)
        self.assertEqual(0, len(qos['queues']))

    def test_clear_minimum_bandwidth_qos(self):
        queue_id_1, port_id_1 = self._create_queue(queue_num=1)
        queue_id_2, port_id_2 = self._create_queue(queue_num=2)
        queue_id_3, _ = self._create_queue()
        queues = {1: queue_id_1, 2: queue_id_2}
        qos_id = self._create_qos(queues=queues)

        # NOTE(ralonsoh): we need to clean only the QoS rule created in this
        # test in order to avoid any interference with other tests.
        qoses = self.ovs._list_qos(_id=self.ovs._min_bw_qos_id)
        with mock.patch.object(self.ovs, '_list_qos') as mock_list_qos:
            mock_list_qos.return_value = qoses
            self.ovs.clear_minimum_bandwidth_qos()
        self.assertIsNone(self._list_qos(qos_id=qos_id))
        self.assertIsNone(self._list_queues(queue_id=queue_id_1))
        self.assertIsNone(self._list_queues(queue_id=queue_id_2))
        self.assertIsNotNone(self._list_queues(queue_id=queue_id_3))

    def test_get_egress_min_bw_for_port(self):
        self.ovs.update_minimum_bandwidth_queue(self.port_id, [], 1, 2800)
        self.assertEqual(
            2800,
            self.ovs.get_egress_min_bw_for_port(port_id=self.port_id))

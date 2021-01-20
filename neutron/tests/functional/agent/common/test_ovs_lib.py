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

import functools

import mock
from neutron_lib import constants as p_const
from neutron_lib.services.qos import constants as qos_constants
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import event
import six

from neutron.agent.common import ovs_lib
from neutron.agent.linux import ip_lib
from neutron.common import utils as common_utils
from neutron.plugins.ml2.drivers.openvswitch.agent.common \
    import constants as ovs_constants
from neutron.tests.functional import base


MIN_RATE_DEFAULT = 1000000
MAX_RATE_DEFAULT = 3000000
BURST_DEFAULT = 2000000
QUEUE_NUM_DEFAULT = 'queue_num'
OTHER_CONFIG_DEFAULT = {six.u('max-rate'): six.u(str(MAX_RATE_DEFAULT)),
                        six.u('burst'): six.u(str(BURST_DEFAULT)),
                        six.u('min-rate'): six.u(str(MIN_RATE_DEFAULT))}


class WaitForPortCreateEvent(event.WaitEvent):
    event_name = 'WaitForPortCreateEvent'

    def __init__(self, port_name):
        table = 'Port'
        events = (self.ROW_CREATE,)
        conditions = (('name', '=', port_name),)
        super(WaitForPortCreateEvent, self).__init__(
            events, table, conditions, timeout=5)


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

    def _create_queue(self, max_kbps=int(MAX_RATE_DEFAULT / 1000),
                      max_burst_kbps=int(BURST_DEFAULT / 1000),
                      min_kbps=int(MIN_RATE_DEFAULT / 1000),
                      neutron_port_id=None, queue_num=None):
        neutron_port_id = (('port-' + uuidutils.generate_uuid())[:13]
                           if not neutron_port_id else neutron_port_id)
        queue_num = QUEUE_NUM_DEFAULT if not queue_num else queue_num
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
        row_event = WaitForPortCreateEvent(port_name)
        self.ovs.ovsdb.idl.notify_handler.watch_event(row_event)
        self.ovs.ovsdb.add_port(self.br_name, port_name).execute(
            check_error=True)
        self.assertTrue(row_event.wait())

    def _find_port_uuid(self, port_name):
        return self.ovs.ovsdb.db_get('Port', port_name, '_uuid').execute()

    def _find_port_qos(self, port_name):
        return self.ovs.ovsdb.db_get('Port', port_name, 'qos').execute()

    def _create_dummy_device(self):
        device_name = ('dummy-' + uuidutils.generate_uuid())[:12]
        ip_lib.IPWrapper().add_dummy(device_name)
        self.elements_to_clean['devices'].append(device_name)
        return device_name

    def _check_value(self, expected_value, retrieve_fn, *args, **kwargs):
        def check_value(ret, keys_to_check):
            ret[0] = retrieve_fn(*args, **kwargs)
            if keys_to_check and isinstance(expected_value, dict):
                for key in keys_to_check:
                    if ret[0][key] != expected_value[key]:
                        return False
                return True
            return ret[0] == expected_value

        ret = [None]
        keys_to_check = kwargs.pop('keys_to_check', None)
        part_check_value = functools.partial(check_value, ret, keys_to_check)
        try:
            common_utils.wait_until_true(part_check_value, timeout=5, sleep=1)
        except common_utils.WaitTimeout:
            self.fail('Expected value: %s, retrieved value: %s' %
                      (expected_value, ret[0]))

    def test__update_queue_new(self):
        queue_id, neutron_port_id = self._create_queue()
        self.assertIsNotNone(queue_id)
        external_ids = {six.u('port'): six.u(neutron_port_id),
                        six.u('queue-num'): six.u('queue_num'),
                        six.u('type'):
                            six.u(qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH)}

        expected = {'_uuid': queue_id,
                    'other_config': OTHER_CONFIG_DEFAULT,
                    'external_ids': external_ids}
        self._check_value(expected, self._list_queues, queue_id)

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
        expected = {'_uuid': queue_id,
                    'other_config': other_config,
                    'external_ids': external_ids}
        self._check_value(expected, self._list_queues, queue_id)

    def test__find_queue(self):
        queue_id, neutron_port_id = self._create_queue()
        external_ids = {six.u('port'): six.u(neutron_port_id),
                        six.u('type'): six.u(
                            qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH),
                        six.u('queue-num'): six.u('queue_num')}
        expected = {'_uuid': queue_id,
                    'external_ids': external_ids,
                    'other_config': OTHER_CONFIG_DEFAULT}
        self._check_value(expected, self.ovs._find_queue, neutron_port_id)

    def test__list_queues(self):
        ports = []
        queue_ids = []
        for _ in range(5):
            queue_id, neutron_port_id = self._create_queue()
            queue_ids.append(queue_id)
            ports.append(neutron_port_id)

        for idx, port in enumerate(ports):
            external_ids = {six.u('port'): six.u(ports[idx]),
                            six.u('type'): six.u(
                                qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH),
                            six.u('queue-num'): six.u('queue_num')}
            expected = {'_uuid': queue_ids[idx],
                        'external_ids': external_ids,
                        'other_config': OTHER_CONFIG_DEFAULT}
            self._check_value([expected], self.ovs._list_queues, port=port,
                              _type=qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH)
            self._check_value([], self.ovs._list_queues, port=port,
                              _type='other_type')

    def test__delete_queue(self):
        queue_id, port_id = self._create_queue()
        external_ids = {six.u('port'): six.u(port_id),
                        six.u('type'): six.u(
                            qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH),
                        six.u('queue-num'): six.u('queue_num')}
        expected = {'_uuid': queue_id,
                    'external_ids': external_ids,
                    'other_config': OTHER_CONFIG_DEFAULT}
        self._check_value(expected, self._list_queues, queue_id=queue_id)

        self.ovs._delete_queue(queue_id)
        self._check_value(None, self._list_queues, queue_id=queue_id)

    def test__update_qos_new(self):
        queue_id, port_id = self._create_queue()
        queues = {1: queue_id}

        qos_id = self._create_qos(queues=queues)
        external_ids = {six.u('id'): six.u(self.ovs._min_bw_qos_id),
                        six.u('_type'): six.u(
                            qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH)}
        expected = {'_uuid': qos_id,
                    'type': 'linux-htb',
                    'external_ids': external_ids}
        self._check_value(expected, self._list_qos, qos_id,
                          keys_to_check=['_uuid', 'type', 'external_ids'])
        qos = self._list_qos(qos_id)
        self.assertEqual(queues[1], qos['queues'][1].uuid)

    def test__update_qos_update(self):
        queue_id_1, _ = self._create_queue()
        queues = {1: queue_id_1}

        qos_id = self._create_qos(queues=queues)
        external_ids = {six.u('id'): six.u(self.ovs._min_bw_qos_id),
                        six.u('_type'): six.u(
                            qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH)}
        expected = {'_uuid': qos_id,
                    'type': 'linux-htb',
                    'external_ids': external_ids}
        self._check_value(expected, self._list_qos, qos_id,
                          keys_to_check=['_uuid', 'type', 'external_ids'])
        qos = self._list_qos(qos_id)
        self.assertEqual(queues[1], qos['queues'][1].uuid)

        queue_id_2, _ = self._create_queue()
        queues[2] = queue_id_2

        self._create_qos(qos_id=qos_id, queues=queues)
        self._check_value(expected, self._list_qos, qos_id,
                          keys_to_check=['_uuid', 'type', 'external_ids'])
        qos = self._list_qos(qos_id)
        self.assertEqual(2, len(qos['queues']))
        self.assertEqual(queues[1], qos['queues'][1].uuid)
        self.assertEqual(queues[2], qos['queues'][2].uuid)

    def test__find_qos(self):
        queue_id, _ = self._create_queue()
        queues = {1: queue_id}
        qos_id = self._create_qos(queues=queues)
        self._check_value((qos_id, queues), self.ovs._find_qos)

    def test__set_port_qos(self):
        port_name = ('port-' + uuidutils.generate_uuid())[:8]
        self._create_bridge()
        self._create_port(port_name)
        self._check_value([], self._find_port_qos, port_name)

        qos_id = self._create_qos()
        self.ovs._set_port_qos(port_name, qos_id=qos_id)
        self._check_value(qos_id, self._find_port_qos, port_name)

        self.ovs._set_port_qos(port_name)
        self._check_value([], self._find_port_qos, port_name)

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
        port_name = ('port-' + uuidutils.generate_uuid())[:8]
        self._create_bridge()
        self._create_port(port_name)
        queue_num = 1
        queue_id, port_id = self._create_queue(neutron_port_id=self.port_id)
        queues = {queue_num: queue_id}
        qos_id = self._create_qos(queues=queues)

        self.ovs.update_minimum_bandwidth_queue(self.port_id, [port_name],
                                                queue_num, 1800)
        self._check_value(qos_id, self._find_port_qos, port_name)
        external_ids = {six.u('port'): six.u(port_id),
                        six.u('type'): six.u(
                            qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH),
                        six.u('queue-num'): six.u('queue_num')}
        other_config = {six.u('max-rate'): six.u(str(MAX_RATE_DEFAULT)),
                        six.u('burst'): six.u(str(BURST_DEFAULT)),
                        six.u('min-rate'): six.u('1800000')}
        expected = {'_uuid': queue_id,
                    'external_ids': external_ids,
                    'other_config': other_config}
        self._check_value(expected, self._list_queues, queue_id)

    def test_update_minimum_bandwidth_queue_no_qos_no_queue(self):
        port_name = ('port-' + uuidutils.generate_uuid())[:8]
        self._create_bridge()
        self._create_port(port_name)
        queue_num = 1

        self.ovs.update_minimum_bandwidth_queue(self.port_id, [port_name],
                                                queue_num, 1700)
        qos_id = self._find_port_qos(port_name)
        qos = self._list_qos(qos_id)
        queue_id = qos['queues'][1].uuid
        external_ids = {six.u('port'): six.u(self.port_id),
                        six.u('type'): six.u(
                            qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH),
                        six.u('queue-num'): six.u(str(queue_num))}
        other_config = {six.u('min-rate'): six.u('1700000')}
        expected = {'_uuid': queue_id,
                    'external_ids': external_ids,
                    'other_config': other_config}
        self._check_value(expected, self._list_queues, queue_id)
        self.elements_to_clean['qoses'].append(qos_id)
        self.elements_to_clean['queues'].append(queue_id)

    def test_delete_minimum_bandwidth_queue(self):
        queue_id_1, neutron_port_id_1 = self._create_queue(queue_num=1)
        queue_id_2, neutron_port_id_2 = self._create_queue(queue_num=2)
        queues = {1: queue_id_1, 2: queue_id_2}
        qos_id = self._create_qos(queues=queues)
        self._check_value({'_uuid': qos_id}, self._list_qos, qos_id,
                          keys_to_check=['_uuid'])
        qos = self._list_qos(qos_id)
        self.assertEqual(queue_id_1, qos['queues'][1].uuid)
        self.assertEqual(queue_id_2, qos['queues'][2].uuid)

        self.ovs.delete_minimum_bandwidth_queue(neutron_port_id_2)
        self._check_value({'_uuid': qos_id}, self._list_qos, qos_id,
                          keys_to_check=['_uuid'])
        qos = self._list_qos(qos_id)
        self.assertEqual(1, len(qos['queues']))
        self.assertEqual(queue_id_1, qos['queues'][1].uuid)

        self.ovs.delete_minimum_bandwidth_queue(neutron_port_id_1)
        self._check_value({'_uuid': qos_id}, self._list_qos, qos_id,
                          keys_to_check=['_uuid'])
        qos = self._list_qos(qos_id)
        self.assertEqual(0, len(qos['queues']))

    def test_delete_minimum_bandwidth_queue_no_qos_found(self):
        queue_id, neutron_port_id = self._create_queue(queue_num=1)
        self.addCleanup(self.ovs._delete_queue, queue_id)

        # Check that it will not raise any exception even if there is no
        # qos with associated queues
        self.ovs.delete_minimum_bandwidth_queue(neutron_port_id)

        # And verify that this queue wasn't in fact deleted as there was no
        # qos found
        queue = self._list_queues(queue_id)
        self.assertEqual(queue_id, queue['_uuid'])

    def test_clear_minimum_bandwidth_qos(self):
        queue_id_1, _ = self._create_queue(queue_num=1)
        queue_id_2, _ = self._create_queue(queue_num=2)
        queue_id_3, port_id_3 = self._create_queue()
        queues = {1: queue_id_1, 2: queue_id_2}
        qos_id = self._create_qos(queues=queues)

        # NOTE(ralonsoh): we need to clean only the QoS rule created in this
        # test in order to avoid any interference with other tests.
        qoses = self.ovs._list_qos(_id=self.ovs._min_bw_qos_id)
        with mock.patch.object(self.ovs, '_list_qos') as mock_list_qos:
            mock_list_qos.return_value = qoses
            self.ovs.clear_minimum_bandwidth_qos()
        self._check_value(None, self._list_qos, qos_id=qos_id)
        self._check_value(None, self._list_queues, queue_id=queue_id_1)
        self._check_value(None, self._list_queues, queue_id=queue_id_2)
        external_ids = {six.u('port'): six.u(port_id_3),
                        six.u('type'): six.u(
                            qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH),
                        six.u('queue-num'): six.u('queue_num')}
        expected = {'_uuid': queue_id_3,
                    'external_ids': external_ids,
                    'other_config': OTHER_CONFIG_DEFAULT}
        self._check_value(expected, self._list_queues, queue_id=queue_id_3)

    def test_get_egress_min_bw_for_port(self):
        self.ovs.update_minimum_bandwidth_queue(self.port_id, [], 1, 2800)
        self._check_value(2800, self.ovs.get_egress_min_bw_for_port,
                          port_id=self.port_id)

    def test_set_controllers_inactivity_probe(self):
        self._create_bridge()
        self.ovs.set_controller(['tcp:127.0.0.1:6633'])
        self.ovs.set_controllers_inactivity_probe(8)
        self.assertEqual(8000,
                         self.ovs.db_get_val('Controller', self.br_name,
                                             'inactivity_probe'))

    def test_add_gre_tunnel_port(self):
        ipv4_tunnel_port = "test-ipv4-port"
        ipv6_tunnel_port = "test-ipv6-port"
        self._create_bridge()
        self.ovs.add_tunnel_port(
            ipv4_tunnel_port, "10.0.0.1", "10.0.0.2",
            tunnel_type=p_const.TYPE_GRE)
        self.ovs.add_tunnel_port(
            ipv6_tunnel_port, "2001:db8::1", "2001:db8:2",
            tunnel_type=p_const.TYPE_GRE)
        interfaces = self.ovs.get_ports_attributes(
            "Interface", columns=["name", "type", "options"],
            if_exists=True)

        ipv4_port_type = None
        ipv6_port_type = None
        ipv6_port_options = {}
        for interface in interfaces:
            if interface['name'] == ipv4_tunnel_port:
                ipv4_port_type = interface['type']
            elif interface['name'] == ipv6_tunnel_port:
                ipv6_port_type = interface['type']
                ipv6_port_options = interface['options']
        self.assertEqual(p_const.TYPE_GRE, ipv4_port_type)
        self.assertEqual(ovs_lib.TYPE_GRE_IP6, ipv6_port_type)
        self.assertEqual('legacy', ipv6_port_options.get('packet_type'))

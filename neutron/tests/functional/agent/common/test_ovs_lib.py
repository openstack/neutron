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
from unittest import mock

from neutron_lib import constants as p_const
from neutron_lib.plugins.ml2 import ovs_constants
from neutron_lib.services.qos import constants as qos_constants
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import event

from neutron.agent.common import ovs_lib
from neutron.agent.linux import ip_lib
from neutron.common import utils as common_utils
from neutron.tests.functional import base


MIN_RATE_DEFAULT = 1000000
MAX_RATE_DEFAULT = 3000000
BURST_DEFAULT = 2000000
QUEUE_NUM_DEFAULT = 'queue_num'
OTHER_CONFIG_DEFAULT = {'max-rate': str(MAX_RATE_DEFAULT),
                        'burst': str(BURST_DEFAULT),
                        'min-rate': str(MIN_RATE_DEFAULT)}


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
        self._check_no_minbw_qos()
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
            self.ovs.ovsdb.db_destroy('QoS', qos).execute(log_errors=False)
        for queue in self.elements_to_clean['queues']:
            self.ovs.ovsdb.db_destroy('Queue', queue).execute(log_errors=False)

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

    def _create_queue(self,
                      queue_type=qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH,
                      max_kbps=int(MAX_RATE_DEFAULT / 1000),
                      max_burst_kbps=int(BURST_DEFAULT / 1000),
                      min_kbps=int(MIN_RATE_DEFAULT / 1000),
                      neutron_port_id=None, queue_num=None):
        neutron_port_id = (('port-' + uuidutils.generate_uuid())[:13]
                           if not neutron_port_id else neutron_port_id)
        queue_num = QUEUE_NUM_DEFAULT if not queue_num else queue_num
        queue_id = self.ovs._update_queue(neutron_port_id, queue_num,
                                          queue_type,
                                          max_kbps=max_kbps,
                                          max_burst_kbps=max_burst_kbps,
                                          min_kbps=min_kbps)

        self.elements_to_clean['queues'].append(queue_id)
        return queue_id, neutron_port_id

    def _create_qos(self, qos_id=None, queues=None,
                    rule_type_id=None,
                    rule_type=qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH):
        qos_id = self.ovs._update_qos(
            rule_type_id, rule_type, qos_id=qos_id, queues=queues)
        self.elements_to_clean['qoses'].append(qos_id)
        return qos_id

    def _list_qos(self, qos_id=None):
        qoses = self.ovs.ovsdb.db_list(
            'QoS',
            columns=('_uuid', 'queues', 'other_config', 'external_ids', 'type')
        ).execute()
        if qos_id:
            for qos in (qos for qos in qoses if qos['_uuid'] == qos_id):
                return qos
            else:
                return None
        return qoses

    def _create_bridge(self, br_name=None):
        br_name = br_name or self.br_name
        self.ovs.ovsdb.add_br(br_name).execute()
        self.elements_to_clean['bridges'].append(br_name)

    def _create_port(self, port_name, br_name=None):
        row_event = WaitForPortCreateEvent(port_name)
        self.ovs.ovsdb.idl.notify_handler.watch_event(row_event)
        self.ovs.ovsdb.add_port(br_name or self.br_name, port_name).execute(
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

    def _check_no_minbw_qos(self):
        """Asserts that there are no min BW qos/queues for this OVS instance"""
        qos_id, qos_queues = self.ovs._find_qos(
            self.ovs._min_bw_qos_id,
            qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH)
        if not qos_id and not qos_queues:
            return

        qos = self.ovs._list_qos(_id=qos_id)
        ovs_queues = self.ovs._list_queues(
            _type=qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH)
        queues = []
        queue_uuids = list(qos_queues.values())
        for ovs_queue in ovs_queues:
            if ovs_queue['_uuid'] in queue_uuids:
                queues.append(str(ovs_queue))

        msg = ('There are QoS/queue registers\nQoS: %s\nqueues: %s' %
               (str(qos), queues))
        self.fail(msg)

    def test__update_queue_new(self):
        queue_id, neutron_port_id = self._create_queue()
        self.assertIsNotNone(queue_id)
        external_ids = {'port': str(neutron_port_id),
                        'queue-num': 'queue_num',
                        'type': qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH}

        expected = {'_uuid': queue_id,
                    'other_config': OTHER_CONFIG_DEFAULT,
                    'external_ids': external_ids}
        self._check_value(expected, self._list_queues, queue_id)

    def test__update_queue_update(self):
        queue_id, neutron_port_id = self._create_queue()
        self.assertIsNotNone(queue_id)
        other_config = {'max-rate': '6000000',
                        'burst': '5000000',
                        'min-rate': '4000000'}
        external_ids = {'port': str(neutron_port_id),
                        'queue-num': 'queue_num',
                        'type': qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH}
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
        external_ids = {'port': str(neutron_port_id),
                        'type': qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH,
                        'queue-num': 'queue_num'}
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
            external_ids = {'port': str(ports[idx]),
                            'type': qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH,
                            'queue-num': 'queue_num'}
            expected = {'_uuid': queue_ids[idx],
                        'external_ids': external_ids,
                        'other_config': OTHER_CONFIG_DEFAULT}
            self._check_value([expected], self.ovs._list_queues, port=port,
                              _type=qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH)
            self._check_value([], self.ovs._list_queues, port=port,
                              _type='other_type')

    def test__delete_queue(self):
        queue_id, port_id = self._create_queue()
        external_ids = {'port': str(port_id),
                        'type': qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH,
                        'queue-num': 'queue_num'}
        expected = {'_uuid': queue_id,
                    'external_ids': external_ids,
                    'other_config': OTHER_CONFIG_DEFAULT}
        self._check_value(expected, self._list_queues, queue_id=queue_id)

        self.ovs._delete_queue(queue_id)
        self._check_value(None, self._list_queues, queue_id=queue_id)

    def test__delete_queue_still_used_in_a_qos(self):
        queue_id, port_id = self._create_queue()
        queues = {1: queue_id}
        qos_id_1 = self._create_qos(
            queues=queues,
            rule_type_id=self.ovs._min_bw_qos_id)
        self.ovs._min_bw_qos_id = uuidutils.generate_uuid()
        qos_id_2 = self._create_qos(
            queues=queues,
            rule_type_id=self.ovs._min_bw_qos_id)
        with mock.patch.object(ovs_lib.LOG, 'error') as mock_error:
            self.assertRaises(RuntimeError, self.ovs._delete_queue,
                              queue_id)

        qoses = ', '.join(sorted([str(qos_id_1), str(qos_id_2)]))
        msg = ('Queue %(queue)s was still in use by the following QoS rules: '
               '%(qoses)s')
        mock_error.assert_called_once_with(
            msg, {'queue': str(queue_id), 'qoses': qoses})

    def test__update_qos_new(self):
        queue_id, port_id = self._create_queue()
        queues = {1: queue_id}

        qos_id = self._create_qos(
            queues=queues,
            rule_type_id=self.ovs._min_bw_qos_id)
        external_ids = {'id': str(self.ovs._min_bw_qos_id),
                        '_type': qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH}
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

        qos_id = self._create_qos(
            queues=queues,
            rule_type_id=self.ovs._min_bw_qos_id)
        external_ids = {'id': str(self.ovs._min_bw_qos_id),
                        '_type': qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH}
        expected = {'_uuid': qos_id,
                    'type': 'linux-htb',
                    'external_ids': external_ids}
        self._check_value(expected, self._list_qos, qos_id,
                          keys_to_check=['_uuid', 'type', 'external_ids'])
        qos = self._list_qos(qos_id)
        self.assertEqual(queues[1], qos['queues'][1].uuid)

        queue_id_2, _ = self._create_queue()
        queues[2] = queue_id_2

        self._create_qos(
            qos_id=qos_id,
            queues=queues,
            rule_type_id=self.ovs._min_bw_qos_id)
        self._check_value(expected, self._list_qos, qos_id,
                          keys_to_check=['_uuid', 'type', 'external_ids'])
        qos = self._list_qos(qos_id)
        self.assertEqual(2, len(qos['queues']))
        self.assertEqual(queues[1], qos['queues'][1].uuid)
        self.assertEqual(queues[2], qos['queues'][2].uuid)

    def test__find_qos(self):
        queue_id, _ = self._create_queue()
        queues = {1: queue_id}
        qos_id = self._create_qos(
            queues=queues,
            rule_type_id=self.ovs._min_bw_qos_id)
        self._check_value((qos_id, queues), self.ovs._find_qos,
                          self.ovs._min_bw_qos_id)

    def test__set_port_qos(self):
        port_name = ('port-' + uuidutils.generate_uuid())[:8]
        self._create_bridge()
        self._create_port(port_name)
        self._check_value([], self._find_port_qos, port_name)

        qos_id = self._create_qos(
            rule_type_id=self.ovs._min_bw_qos_id)
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

    def test_egress_bw_limit(self):
        port_name = ('port-' + uuidutils.generate_uuid())[:8]
        self._create_bridge()
        self._create_port(port_name)
        self.ovs.create_egress_bw_limit_for_port(port_name, 700, 70)
        max_rate, burst = self.ovs.get_egress_bw_limit_for_port(port_name)
        self.assertEqual(700, max_rate)
        self.assertEqual(70, burst)
        self.ovs.delete_egress_bw_limit_for_port(port_name)
        max_rate, burst = self.ovs.get_egress_bw_limit_for_port(port_name)
        self.assertIsNone(max_rate)
        self.assertIsNone(burst)

    def test_set_pkt_mark_for_ingress_bandwidth_limit(self):
        self._create_bridge()
        self.ovs.set_queue_for_ingress_bandwidth_limit()
        flows = self.ovs.dump_flows_for_table(ovs_constants.LOCAL_SWITCHING)
        expected = (
            'priority=200,reg3=0 '
            'actions=set_queue:%(queue_num)s,'
            'load:0x1->NXM_NX_REG3[0],resubmit(,0)' % {
                'queue_num': ovs_lib.QOS_DEFAULT_QUEUE
            }
        )
        self.assertIn(expected, flows)

    def test_ingress_bw_limit(self):
        port_name = ('port-' + uuidutils.generate_uuid())[:8]
        self._create_bridge()
        self._create_port(port_name)
        self.ovs.update_ingress_bw_limit_for_port(port_name, 700, 70)
        qos_id = self._find_port_qos(port_name)
        qos = self._list_qos(qos_id)
        queue_id = qos['queues'][0].uuid
        external_ids = {'port': str(port_name),
                        'type': qos_constants.RULE_TYPE_BANDWIDTH_LIMIT,
                        'queue-num': '0'}
        other_config = {'burst': '70000',
                        'max-rate': '700000'}
        expected = {'_uuid': queue_id,
                    'external_ids': external_ids,
                    'other_config': other_config}

        self._check_value(expected, self._list_queues, queue_id)
        self.elements_to_clean['qoses'].append(qos_id)
        self.elements_to_clean['queues'].append(queue_id)

        self.ovs.update_ingress_bw_limit_for_port(port_name, 750, 100)
        expected['other_config'] = {'burst': '100000',
                                    'max-rate': '750000'}

        self.ovs.delete_ingress_bw_limit_for_port(port_name)
        self.assertIsNone(self._list_qos(qos_id))

    def test_ingress_bw_limit_dpdk_port(self):
        port_name = ('port-' + uuidutils.generate_uuid())[:8]
        self._create_bridge()
        self._create_port(port_name)
        self.ovs.ovsdb.db_set(
            'Interface', port_name,
            ('type', ovs_constants.OVS_DPDK_VHOST_USER)).execute()
        self.ovs.update_ingress_bw_limit_for_port(port_name, 700, 70)
        qos_id = self._find_port_qos(port_name)
        external_ids = {'id': str(port_name)}
        other_config = {'cir': str(700 * p_const.SI_BASE // 8),
                        'cbs': str(70 * p_const.SI_BASE // 8)}
        expected = {'_uuid': qos_id,
                    'external_ids': external_ids,
                    'other_config': other_config,
                    'queues': {},
                    'type': 'egress-policer'}
        self._check_value(expected, self._list_qos, qos_id)

        self.ovs.update_ingress_bw_limit_for_port(port_name, 750, 100)
        expected['other_config'] = {'cir': str(750 * p_const.SI_BASE // 8),
                                    'cbs': str(100 * p_const.SI_BASE // 8)}
        self._check_value(expected, self._list_qos, qos_id)

        self.ovs.delete_ingress_bw_limit_for_port(port_name)
        qos = self._list_qos(qos_id)
        self.assertEqual(0, len(qos['queues']))

    def test__set_pkt_mark_for_minimum_bandwidth(self):
        self._create_bridge()
        self.ovs._set_pkt_mark_for_minimum_bandwidth(1234)
        flows = self.ovs.dump_flows_for_table(ovs_constants.LOCAL_SWITCHING)
        # NOTE(slaweq) 1234 in dec is 0x4d2,
        # action set_field:1234->pkt mark is shown in the OF output as
        # load:0x4d2->NXM_NX_PKT_MARK[]
        expected = ('priority=200,reg4=0,in_port=1234 '
                    'actions=load:0x4d2->NXM_NX_PKT_MARK[],'
                    'load:0x1->NXM_NX_REG4[0],resubmit(,0)')
        self.assertIn(expected, flows)

    def test__unset_pkt_mark_for_minimum_bandwidth(self):
        self.test__set_pkt_mark_for_minimum_bandwidth()

        self.ovs._unset_pkt_mark_for_minimum_bandwidth(1234)
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
        qos_id = self._create_qos(
            queues=queues,
            rule_type_id=self.ovs._min_bw_qos_id)
        self.ovs.update_minimum_bandwidth_queue(self.port_id, [port_name],
                                                queue_num, 1800)
        self._check_value(qos_id, self._find_port_qos, port_name)
        external_ids = {'port': str(port_id),
                        'type': qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH,
                        'queue-num': 'queue_num'}
        other_config = {'max-rate': str(MAX_RATE_DEFAULT),
                        'burst': str(BURST_DEFAULT),
                        'min-rate': '1800000'}
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
        external_ids = {'port': str(self.port_id),
                        'type': qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH,
                        'queue-num': str(queue_num)}
        other_config = {'min-rate': '1700000',
                        'max-rate': str(ovs_lib.OVS_MAX_RATE)}
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
        qos_id = self._create_qos(
            queues=queues,
            rule_type_id=self.ovs._min_bw_qos_id)
        self._check_value({'_uuid': qos_id}, self._list_qos, qos_id,
                          keys_to_check=['_uuid'])

        # Assign the QoS policy to the physical bridge interface. This QoS
        # must be unset once the minimum bandwidth queue is removed.
        br_phy = ('br-phy-' + uuidutils.generate_uuid())[:6]
        ext_port = ('phy-' + uuidutils.generate_uuid())[:9]
        self._create_bridge(br_name=br_phy)
        self._create_port(ext_port, br_name=br_phy)
        self.ovs._set_port_qos(ext_port, qos_id=qos_id)

        qos = self._list_qos(qos_id)
        self.assertEqual(queue_id_1, qos['queues'][1].uuid)
        self.assertEqual(queue_id_2, qos['queues'][2].uuid)

        self.ovs.delete_minimum_bandwidth_queue(neutron_port_id_2)
        self._check_value({'_uuid': qos_id}, self._list_qos, qos_id,
                          keys_to_check=['_uuid'])
        qos = self._list_qos(qos_id)
        self.assertEqual(1, len(qos['queues']))
        self.assertEqual(queue_id_1, qos['queues'][1].uuid)
        ports_with_qos = self.ovs.ovsdb.db_find(
            'Port', ('qos', '=', qos_id)).execute(check_error=True)
        self.assertEqual(1, len(ports_with_qos))
        self.assertEqual(ext_port, ports_with_qos[0]['name'])

        self.ovs.delete_minimum_bandwidth_queue(neutron_port_id_1)
        self.assertIsNone(self._list_qos(qos_id))
        ports_with_qos = self.ovs.ovsdb.db_find(
            'Port', ('qos', '=', qos_id)).execute(check_error=True)
        self.assertEqual(0, len(ports_with_qos))

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

    def test_clear_bandwidth_qos(self):
        queue_id_1, _ = self._create_queue(queue_num=1)
        queue_id_2, _ = self._create_queue(queue_num=2)
        queue_id_3, port_id_3 = self._create_queue()
        queues = {1: queue_id_1, 2: queue_id_2}
        qos_id = self._create_qos(
            queues=queues,
            rule_type_id=self.ovs._min_bw_qos_id)

        # NOTE(ralonsoh): we need to clean only the QoS rule created in this
        # test in order to avoid any interference with other tests.
        qoses = self.ovs._list_qos(_id=self.ovs._min_bw_qos_id)
        with mock.patch.object(self.ovs, '_list_qos') as mock_list_qos:
            mock_list_qos.side_effect = [qoses, []]
            self.ovs.clear_bandwidth_qos()
        self._check_value(None, self._list_qos, qos_id=qos_id)
        self._check_value(None, self._list_queues, queue_id=queue_id_1)
        self._check_value(None, self._list_queues, queue_id=queue_id_2)
        external_ids = {'port': str(port_id_3),
                        'type': qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH,
                        'queue-num': 'queue_num'}
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
        self.assertEqual('legacy_l2', ipv6_port_options.get('packet_type'))

    def test_set_igmp_snooping_flood(self):
        port_name = 'test_output_port_2'
        self._create_bridge()
        self._create_port(port_name)
        self.ovs.set_igmp_snooping_flood(port_name, True)
        ports_other_config = self.ovs.db_get_val('Port', port_name,
                                                 'other_config')
        self.assertEqual(
            'true',
            ports_other_config.get('mcast-snooping-flood', '').lower())
        self.assertEqual(
            'true',
            ports_other_config.get('mcast-snooping-flood-reports', '').lower())

        self.ovs.set_igmp_snooping_flood(port_name, False)
        ports_other_config = self.ovs.db_get_val('Port', port_name,
                                                 'other_config')
        self.assertEqual(
            'false',
            ports_other_config.get('mcast-snooping-flood', '').lower())
        self.assertEqual(
            'false',
            ports_other_config.get('mcast-snooping-flood-reports', '').lower())

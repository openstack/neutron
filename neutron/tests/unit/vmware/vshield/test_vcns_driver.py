# Copyright 2013 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from eventlet import greenthread
import mock

from neutron.plugins.vmware.vshield.common import constants as vcns_const
from neutron.plugins.vmware.vshield.tasks import constants as ts_const
from neutron.plugins.vmware.vshield.tasks import tasks as ts
from neutron.plugins.vmware.vshield import vcns_driver
from neutron.tests import base
from neutron.tests.unit import vmware
from neutron.tests.unit.vmware.vshield import fake_vcns

VCNS_CONFIG_FILE = vmware.get_fake_conf("vcns.ini.test")

ts.TaskManager.set_default_interval(100)


class VcnsDriverTaskManagerTestCase(base.BaseTestCase):

    def setUp(self):
        super(VcnsDriverTaskManagerTestCase, self).setUp()
        self.manager = ts.TaskManager()
        self.manager.start(100)

    def tearDown(self):
        self.manager.stop()
        # Task manager should not leave running threads around
        # if _thread is None it means it was killed in stop()
        self.assertIsNone(self.manager._thread)
        super(VcnsDriverTaskManagerTestCase, self).tearDown()

    def _test_task_manager_task_process_state(self, sync_exec=False):
        def _task_failed(task, reason):
            task.userdata['result'] = False
            task.userdata['error'] = reason

        def _check_state(task, exp_state):
            if not task.userdata.get('result', True):
                return False

            state = task.userdata['state']
            if state != exp_state:
                msg = "state %d expect %d" % (
                    state, exp_state)
                _task_failed(task, msg)
                return False

            task.userdata['state'] = state + 1
            return True

        def _exec(task):
            if not _check_state(task, 1):
                return ts_const.TaskStatus.ERROR

            if task.userdata['sync_exec']:
                return ts_const.TaskStatus.COMPLETED
            else:
                return ts_const.TaskStatus.PENDING

        def _status(task):
            if task.userdata['sync_exec']:
                _task_failed(task, "_status callback triggered")

            state = task.userdata['state']
            if state == 3:
                _check_state(task, 3)
                return ts_const.TaskStatus.PENDING
            else:
                _check_state(task, 4)
                return ts_const.TaskStatus.COMPLETED

        def _result(task):
            if task.userdata['sync_exec']:
                exp_state = 3
            else:
                exp_state = 5

            _check_state(task, exp_state)

        def _start_monitor(task):
            _check_state(task, 0)

        def _executed_monitor(task):
            _check_state(task, 2)

        def _result_monitor(task):
            if task.userdata['sync_exec']:
                exp_state = 4
            else:
                exp_state = 6

            if _check_state(task, exp_state):
                task.userdata['result'] = True
            else:
                task.userdata['result'] = False

        userdata = {
            'state': 0,
            'sync_exec': sync_exec
        }
        task = ts.Task('name', 'res', _exec, _status, _result, userdata)
        task.add_start_monitor(_start_monitor)
        task.add_executed_monitor(_executed_monitor)
        task.add_result_monitor(_result_monitor)

        self.manager.add(task)

        task.wait(ts_const.TaskState.RESULT)

        self.assertTrue(userdata['result'])

    def test_task_manager_task_sync_exec_process_state(self):
        self._test_task_manager_task_process_state(sync_exec=True)

    def test_task_manager_task_async_exec_process_state(self):
        self._test_task_manager_task_process_state(sync_exec=False)

    def test_task_manager_task_ordered_process(self):
        def _task_failed(task, reason):
            task.userdata['result'] = False
            task.userdata['error'] = reason

        def _exec(task):
            task.userdata['executed'] = True
            return ts_const.TaskStatus.PENDING

        def _status(task):
            return ts_const.TaskStatus.COMPLETED

        def _result(task):
            next_task = task.userdata.get('next')
            if next_task:
                if next_task.userdata.get('executed'):
                    _task_failed(next_task, "executed premature")
            if task.userdata.get('result', True):
                task.userdata['result'] = True

        tasks = []
        prev = None
        last_task = None
        for i in range(5):
            name = "name-%d" % i
            task = ts.Task(name, 'res', _exec, _status, _result, {})
            tasks.append(task)
            if prev:
                prev.userdata['next'] = task
            prev = task
            last_task = task

        for task in tasks:
            self.manager.add(task)

        last_task.wait(ts_const.TaskState.RESULT)

        for task in tasks:
            self.assertTrue(task.userdata['result'])

    def test_task_manager_task_parallel_process(self):
        tasks = []

        def _exec(task):
            task.userdata['executed'] = True
            return ts_const.TaskStatus.PENDING

        def _status(task):
            for t in tasks:
                if not t.userdata.get('executed'):
                    t.userdata['resut'] = False
            return ts_const.TaskStatus.COMPLETED

        def _result(task):
            if (task.userdata.get('result') is None and
                task.status == ts_const.TaskStatus.COMPLETED):
                task.userdata['result'] = True
            else:
                task.userdata['result'] = False

        for i in range(5):
            name = "name-%d" % i
            res = 'resource-%d' % i
            task = ts.Task(name, res, _exec, _status, _result, {})
            tasks.append(task)
            self.manager.add(task)

        for task in tasks:
            task.wait(ts_const.TaskState.RESULT)
            self.assertTrue(task.userdata['result'])

    def _test_task_manager_stop(self, exec_wait=False, result_wait=False,
                                stop_wait=0):
        def _exec(task):
            if exec_wait:
                greenthread.sleep(0.01)
            return ts_const.TaskStatus.PENDING

        def _status(task):
            greenthread.sleep(0.01)
            return ts_const.TaskStatus.PENDING

        def _result(task):
            if result_wait:
                greenthread.sleep(0)
            pass

        manager = ts.TaskManager().start(100)
        manager.stop()
        # Task manager should not leave running threads around
        # if _thread is None it means it was killed in stop()
        self.assertIsNone(manager._thread)
        manager.start(100)

        alltasks = {}
        for i in range(100):
            res = 'res-%d' % i
            tasks = []
            for i in range(100):
                task = ts.Task('name', res, _exec, _status, _result)
                manager.add(task)
                tasks.append(task)
            alltasks[res] = tasks

        greenthread.sleep(stop_wait)
        manager.stop()
        # Task manager should not leave running threads around
        # if _thread is None it means it was killed in stop()
        self.assertIsNone(manager._thread)

        for res, tasks in alltasks.iteritems():
            for task in tasks:
                self.assertEqual(task.status, ts_const.TaskStatus.ABORT)

    def test_task_manager_stop_1(self):
        self._test_task_manager_stop(True, True, 0)

    def test_task_manager_stop_2(self):
        self._test_task_manager_stop(True, True, 1)

    def test_task_manager_stop_3(self):
        self._test_task_manager_stop(False, False, 0)

    def test_task_manager_stop_4(self):
        self._test_task_manager_stop(False, False, 1)

    def test_task_pending_task(self):
        def _exec(task):
            task.userdata['executing'] = True
            while not task.userdata['tested']:
                greenthread.sleep(0)
            task.userdata['executing'] = False
            return ts_const.TaskStatus.COMPLETED

        userdata = {
            'executing': False,
            'tested': False
        }
        manager = ts.TaskManager().start(100)
        task = ts.Task('name', 'res', _exec, userdata=userdata)
        manager.add(task)

        while not userdata['executing']:
            greenthread.sleep(0)
        self.assertTrue(manager.has_pending_task())

        userdata['tested'] = True
        while userdata['executing']:
            greenthread.sleep(0)
        self.assertFalse(manager.has_pending_task())


class VcnsDriverTestCase(base.BaseTestCase):

    def vcns_patch(self):
        instance = self.mock_vcns.start()
        instance.return_value.deploy_edge.side_effect = self.fc.deploy_edge
        instance.return_value.get_edge_id.side_effect = self.fc.get_edge_id
        instance.return_value.get_edge_deploy_status.side_effect = (
            self.fc.get_edge_deploy_status)
        instance.return_value.delete_edge.side_effect = self.fc.delete_edge
        instance.return_value.update_interface.side_effect = (
            self.fc.update_interface)
        instance.return_value.get_nat_config.side_effect = (
            self.fc.get_nat_config)
        instance.return_value.update_nat_config.side_effect = (
            self.fc.update_nat_config)
        instance.return_value.delete_nat_rule.side_effect = (
            self.fc.delete_nat_rule)
        instance.return_value.get_edge_status.side_effect = (
            self.fc.get_edge_status)
        instance.return_value.get_edges.side_effect = self.fc.get_edges
        instance.return_value.update_routes.side_effect = (
            self.fc.update_routes)
        instance.return_value.create_lswitch.side_effect = (
            self.fc.create_lswitch)
        instance.return_value.delete_lswitch.side_effect = (
            self.fc.delete_lswitch)

    def setUp(self):
        super(VcnsDriverTestCase, self).setUp()

        self.config_parse(args=['--config-file', VCNS_CONFIG_FILE])

        self.fc = fake_vcns.FakeVcns()
        self.mock_vcns = mock.patch(vmware.VCNS_NAME, autospec=True)
        self.vcns_patch()

        self.addCleanup(self.fc.reset_all)

        self.vcns_driver = vcns_driver.VcnsDriver(self)

        self.edge_id = None
        self.result = None

    def tearDown(self):
        self.vcns_driver.task_manager.stop()
        # Task manager should not leave running threads around
        # if _thread is None it means it was killed in stop()
        self.assertIsNone(self.vcns_driver.task_manager._thread)
        super(VcnsDriverTestCase, self).tearDown()

    def _deploy_edge(self):
        task = self.vcns_driver.deploy_edge(
            'router-id', 'myedge', 'internal-network', {}, wait_for_exec=True)
        self.assertEqual(self.edge_id, 'edge-1')
        task.wait(ts_const.TaskState.RESULT)
        return task

    def edge_deploy_started(self, task):
        self.edge_id = task.userdata['edge_id']

    def edge_deploy_result(self, task):
        if task.status == ts_const.TaskStatus.COMPLETED:
            task.userdata['jobdata']['edge_deploy_result'] = True

    def edge_delete_result(self, task):
        if task.status == ts_const.TaskStatus.COMPLETED:
            task.userdata['jobdata']['edge_delete_result'] = True

    def snat_create_result(self, task):
        if task.status == ts_const.TaskStatus.COMPLETED:
            task.userdata['jobdata']['snat_create_result'] = True

    def snat_delete_result(self, task):
        if task.status == ts_const.TaskStatus.COMPLETED:
            task.userdata['jobdata']['snat_delete_result'] = True

    def dnat_create_result(self, task):
        if task.status == ts_const.TaskStatus.COMPLETED:
            task.userdata['jobdata']['dnat_create_result'] = True

    def dnat_delete_result(self, task):
        if task.status == ts_const.TaskStatus.COMPLETED:
            task.userdata['jobdata']['dnat_delete_result'] = True

    def nat_update_result(self, task):
        if task.status == ts_const.TaskStatus.COMPLETED:
            task.userdata['jobdata']['nat_update_result'] = True

    def routes_update_result(self, task):
        if task.status == ts_const.TaskStatus.COMPLETED:
            task.userdata['jobdata']['routes_update_result'] = True

    def interface_update_result(self, task):
        if task.status == ts_const.TaskStatus.COMPLETED:
            task.userdata['jobdata']['interface_update_result'] = True

    def test_deploy_edge(self):
        jobdata = {}
        task = self.vcns_driver.deploy_edge(
            'router-id', 'myedge', 'internal-network', jobdata=jobdata,
            wait_for_exec=True)
        self.assertEqual(self.edge_id, 'edge-1')
        task.wait(ts_const.TaskState.RESULT)
        self.assertEqual(task.status, ts_const.TaskStatus.COMPLETED)
        self.assertTrue(jobdata.get('edge_deploy_result'))

    def test_deploy_edge_fail(self):
        task1 = self.vcns_driver.deploy_edge(
            'router-1', 'myedge', 'internal-network', {}, wait_for_exec=True)
        task2 = self.vcns_driver.deploy_edge(
            'router-2', 'myedge', 'internal-network', {}, wait_for_exec=True)
        task1.wait(ts_const.TaskState.RESULT)
        task2.wait(ts_const.TaskState.RESULT)
        self.assertEqual(task2.status, ts_const.TaskStatus.ERROR)

    def test_get_edge_status(self):
        self._deploy_edge()
        status = self.vcns_driver.get_edge_status(self.edge_id)
        self.assertEqual(status, vcns_const.RouterStatus.ROUTER_STATUS_ACTIVE)

    def test_get_edges(self):
        self._deploy_edge()
        edges = self.vcns_driver.get_edges_statuses()
        found = False
        for edge_id, status in edges.iteritems():
            if edge_id == self.edge_id:
                found = True
                break
        self.assertTrue(found)

    def _create_nat_rule(self, edge_id, action, org, translated):
        jobdata = {}
        if action == 'snat':
            task = self.vcns_driver.create_snat_rule(
                'router-id', edge_id, org, translated, jobdata=jobdata)
            key = 'snat_create_result'
        else:
            task = self.vcns_driver.create_dnat_rule(
                'router-id', edge_id, org, translated, jobdata=jobdata)
            key = 'dnat_create_result'
        task.wait(ts_const.TaskState.RESULT)
        self.assertTrue(jobdata.get(key))

    def _delete_nat_rule(self, edge_id, action, addr):
        jobdata = {}
        if action == 'snat':
            task = self.vcns_driver.delete_snat_rule(
                'router-id', edge_id, addr, jobdata=jobdata)
            key = 'snat_delete_result'
        else:
            task = self.vcns_driver.delete_dnat_rule(
                'router-id', edge_id, addr, jobdata=jobdata)
            key = 'dnat_delete_result'
        task.wait(ts_const.TaskState.RESULT)
        self.assertTrue(jobdata.get(key))

    def _test_create_nat_rule(self, action):
        self._deploy_edge()
        addr = '192.168.1.1'
        translated = '10.0.0.1'
        self._create_nat_rule(self.edge_id, action, addr, translated)

        natcfg = self.vcns_driver.get_nat_config(self.edge_id)
        for rule in natcfg['rules']['natRulesDtos']:
            if (rule['originalAddress'] == addr and
                rule['translatedAddress'] == translated and
                rule['action'] == action):
                break
        else:
            self.assertTrue(False)

    def _test_delete_nat_rule(self, action):
        self._deploy_edge()
        addr = '192.168.1.1'
        translated = '10.0.0.1'
        self._create_nat_rule(self.edge_id, action, addr, translated)
        if action == 'snat':
            self._delete_nat_rule(self.edge_id, action, addr)
        else:
            self._delete_nat_rule(self.edge_id, action, translated)
        natcfg = self.vcns_driver.get_nat_config(self.edge_id)
        for rule in natcfg['rules']['natRulesDtos']:
            if (rule['originalAddress'] == addr and
                rule['translatedAddress'] == translated and
                rule['action'] == action):
                self.assertTrue(False)
                break

    def test_create_snat_rule(self):
        self._test_create_nat_rule('snat')

    def test_delete_snat_rule(self):
        self._test_delete_nat_rule('snat')

    def test_create_dnat_rule(self):
        self._test_create_nat_rule('dnat')

    def test_delete_dnat_rule(self):
        self._test_delete_nat_rule('dnat')

    def test_update_nat_rules(self):
        self._deploy_edge()
        jobdata = {}
        snats = [{
            'src': '192.168.1.0/24',
            'translated': '10.0.0.1'
        }, {
            'src': '192.168.2.0/24',
            'translated': '10.0.0.2'
        }, {
            'src': '192.168.3.0/24',
            'translated': '10.0.0.3'
        }
        ]
        dnats = [{
            'dst': '100.0.0.4',
            'translated': '192.168.1.1'
        }, {
            'dst': '100.0.0.5',
            'translated': '192.168.2.1'
        }
        ]
        task = self.vcns_driver.update_nat_rules(
            'router-id', self.edge_id, snats, dnats, jobdata=jobdata)
        task.wait(ts_const.TaskState.RESULT)
        self.assertTrue(jobdata.get('nat_update_result'))

        natcfg = self.vcns_driver.get_nat_config(self.edge_id)
        rules = natcfg['rules']['natRulesDtos']
        self.assertEqual(len(rules), 2 * len(dnats) + len(snats))
        self.natEquals(rules[0], dnats[0])
        self.natEquals(rules[1], self.snat_for_dnat(dnats[0]))
        self.natEquals(rules[2], dnats[1])
        self.natEquals(rules[3], self.snat_for_dnat(dnats[1]))
        self.natEquals(rules[4], snats[0])
        self.natEquals(rules[5], snats[1])
        self.natEquals(rules[6], snats[2])

    def snat_for_dnat(self, dnat):
        return {
            'src': dnat['translated'],
            'translated': dnat['dst']
        }

    def natEquals(self, rule, exp):
        addr = exp.get('src')
        if not addr:
            addr = exp.get('dst')

        self.assertEqual(rule['originalAddress'], addr)
        self.assertEqual(rule['translatedAddress'], exp['translated'])

    def test_update_routes(self):
        self._deploy_edge()
        jobdata = {}
        routes = [{
            'cidr': '192.168.1.0/24',
            'nexthop': '169.254.2.1'
        }, {
            'cidr': '192.168.2.0/24',
            'nexthop': '169.254.2.1'
        }, {
            'cidr': '192.168.3.0/24',
            'nexthop': '169.254.2.1'
        }
        ]
        task = self.vcns_driver.update_routes(
            'router-id', self.edge_id, '10.0.0.1', routes, jobdata=jobdata)
        task.wait(ts_const.TaskState.RESULT)
        self.assertTrue(jobdata.get('routes_update_result'))

    def test_update_interface(self):
        self._deploy_edge()
        jobdata = {}
        task = self.vcns_driver.update_interface(
            'router-id', self.edge_id, vcns_const.EXTERNAL_VNIC_INDEX,
            'network-id', address='100.0.0.3', netmask='255.255.255.0',
            jobdata=jobdata)
        task.wait(ts_const.TaskState.RESULT)
        self.assertTrue(jobdata.get('interface_update_result'))

    def test_delete_edge(self):
        self._deploy_edge()
        jobdata = {}
        task = self.vcns_driver.delete_edge(
            'router-id', self.edge_id, jobdata=jobdata)
        task.wait(ts_const.TaskState.RESULT)
        self.assertTrue(jobdata.get('edge_delete_result'))

    def test_create_lswitch(self):
        tz_config = [{
            'transport_zone_uuid': 'tz-uuid'
        }]
        lswitch = self.vcns_driver.create_lswitch('lswitch', tz_config)
        self.assertEqual(lswitch['display_name'], 'lswitch')
        self.assertEqual(lswitch['type'], 'LogicalSwitchConfig')
        self.assertIn('uuid', lswitch)

    def test_delete_lswitch(self):
        tz_config = {
            'transport_zone_uuid': 'tz-uuid'
        }
        lswitch = self.vcns_driver.create_lswitch('lswitch', tz_config)
        self.vcns_driver.delete_lswitch(lswitch['uuid'])

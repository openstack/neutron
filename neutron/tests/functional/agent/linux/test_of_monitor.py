# Copyright 2019 Red Hat, Inc.
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

from neutron.agent.linux import of_monitor
from neutron.common import utils
from neutron.tests.common import net_helpers
from neutron.tests.functional import base as functional_base


class OFMonitorTestCase(functional_base.BaseSudoTestCase):

    DEFAULT_FLOW = {'table': 0, 'cookie': '0', 'actions': 'NORMAL'}

    def setUp(self):
        super(OFMonitorTestCase, self).setUp()
        self.bridge = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        self.of_monitor = of_monitor.OFMonitor(self.bridge.br_name,
                                               start=False)
        self.addCleanup(self.of_monitor.stop)

    def _format_flow(self, flow, event_type):
        deleted = ''
        if event_type == 'DELETED':
            deleted = 'reason=delete'
        table = 'table=%s' % flow['table']
        cookie = flow.get('cookie') or hex(self.bridge._default_cookie)
        # NOTE(ralonsoh): remove PY2 "L" suffix in longs
        cookie = 'cookie=' + cookie.rstrip('L')
        filters = []
        if flow.get('in_port'):
            filters.append('in_port=%s' % flow.get('in_port'))
        if flow.get('dl_vlan'):
            filters.append('dl_vlan=%s' % flow.get('dl_vlan'))
        if flow.get('dl_src'):
            filters.append('dl_src=%s' % flow.get('dl_src'))
        filters = ','.join(filters)
        actions = ''
        if flow.get('actions'):
            actions += 'actions=%s' % flow.get('actions')
        flow_sections = [section for section
                         in (deleted, table, cookie, filters, actions)
                         if section]
        return ' '.join(flow_sections)

    def _check_flow(self, reference_flow, event_type):
        def _read_and_check():
            event = self.of_monitor.of_events
            if len(event) == 1:
                events_container.append(event[0])
                return True
            return False

        events_container = []
        try:
            utils.wait_until_true(_read_and_check, timeout=5)
        except utils.WaitTimeout:
            self.fail('Flow "%s" with action %s not found' % (reference_flow,
                                                              event_type))
        event = events_container.pop()
        self.assertEqual(event_type, event.event_type)
        self.assertEqual(self._format_flow(reference_flow, event_type),
                         event.flow)

    def test_of_events(self):
        self.of_monitor.start()
        self._check_flow(self.DEFAULT_FLOW, 'ADDED')

        flow = {'table': 10, 'in_port': 20, 'dl_vlan': 30,
                'dl_src': '00:00:00:00:00:01', 'actions': 'NORMAL'}
        self.bridge.add_flow(**flow)
        self._check_flow(flow, 'ADDED')

        flow['table'] = 50
        self.bridge.add_flow(**flow)
        self._check_flow(flow, 'ADDED')

        flow['actions'] = 'resubmit:100'
        self.bridge.mod_flow(**flow)
        self._check_flow(flow, 'MODIFIED')

        flow['table'] = 10
        flow['actions'] = 'NORMAL'
        flow_to_delete = flow.copy()
        flow_to_delete.pop('actions')
        self.bridge.delete_flows(**flow_to_delete)
        self._check_flow(flow, 'DELETED')

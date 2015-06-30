# Copyright (c) 2013 OpenStack Foundation
# Copyright 2013, Nachi Ueno, NTT MCL, Inc.
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

import math
import mock

from neutron.common import constants as const
from neutron import context
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from neutron.tests import tools
from neutron.tests.unit.agent import test_securitygroups_rpc as test_sg_rpc
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.extensions import test_securitygroup as test_sg

PLUGIN_NAME = 'neutron.plugins.ml2.plugin.Ml2Plugin'
NOTIFIER = 'neutron.plugins.ml2.rpc.AgentNotifierApi'


class Ml2SecurityGroupsTestCase(test_sg.SecurityGroupDBTestCase):
    _plugin_name = PLUGIN_NAME

    def setUp(self, plugin=None):
        test_sg_rpc.set_firewall_driver(test_sg_rpc.FIREWALL_HYBRID_DRIVER)
        notifier_p = mock.patch(NOTIFIER)
        notifier_cls = notifier_p.start()
        self.notifier = mock.Mock()
        notifier_cls.return_value = self.notifier
        self.useFixture(tools.AttributeMapMemento())
        super(Ml2SecurityGroupsTestCase, self).setUp(PLUGIN_NAME)

    def tearDown(self):
        super(Ml2SecurityGroupsTestCase, self).tearDown()


class TestMl2SecurityGroups(Ml2SecurityGroupsTestCase,
                            test_sg.TestSecurityGroups,
                            test_sg_rpc.SGNotificationTestMixin):
    def setUp(self):
        super(TestMl2SecurityGroups, self).setUp()
        self.ctx = context.get_admin_context()
        plugin = manager.NeutronManager.get_plugin()
        plugin.start_rpc_listeners()

    def _make_port_with_new_sec_group(self, net_id):
        sg = self._make_security_group(self.fmt, 'name', 'desc')
        port = self._make_port(
            self.fmt, net_id, security_groups=[sg['security_group']['id']])
        return port['port']

    def _make_port_without_sec_group(self, net_id):
        port = self._make_port(
            self.fmt, net_id, security_groups=[])
        return port['port']

    def test_security_group_get_ports_from_devices(self):
        with self.network() as n:
            with self.subnet(n):
                orig_ports = [
                    self._make_port_with_new_sec_group(n['network']['id']),
                    self._make_port_with_new_sec_group(n['network']['id']),
                    self._make_port_without_sec_group(n['network']['id'])
                ]
                plugin = manager.NeutronManager.get_plugin()
                # should match full ID and starting chars
                ports = plugin.get_ports_from_devices(self.ctx,
                    [orig_ports[0]['id'], orig_ports[1]['id'][0:8],
                     orig_ports[2]['id']])
                self.assertEqual(len(orig_ports), len(ports))
                for port_dict in ports:
                    p = next(p for p in orig_ports
                             if p['id'] == port_dict['id'])
                    self.assertEqual(p['id'], port_dict['id'])
                    self.assertEqual(p['security_groups'],
                                     port_dict[ext_sg.SECURITYGROUPS])
                    self.assertEqual([], port_dict['security_group_rules'])
                    self.assertEqual([p['fixed_ips'][0]['ip_address']],
                                     port_dict['fixed_ips'])
                    self._delete('ports', p['id'])

    def test_security_group_get_ports_from_devices_with_bad_id(self):
        plugin = manager.NeutronManager.get_plugin()
        ports = plugin.get_ports_from_devices(self.ctx, ['bad_device_id'])
        self.assertFalse(ports)

    def test_security_group_no_db_calls_with_no_ports(self):
        plugin = manager.NeutronManager.get_plugin()
        with mock.patch(
            'neutron.plugins.ml2.db.get_sg_ids_grouped_by_port'
        ) as get_mock:
            self.assertFalse(plugin.get_ports_from_devices(self.ctx, []))
            self.assertFalse(get_mock.called)

    def test_large_port_count_broken_into_parts(self):
        plugin = manager.NeutronManager.get_plugin()
        max_ports_per_query = 5
        ports_to_query = 73
        for max_ports_per_query in (1, 2, 5, 7, 9, 31):
            with mock.patch('neutron.plugins.ml2.db.MAX_PORTS_PER_QUERY',
                            new=max_ports_per_query),\
                    mock.patch(
                        'neutron.plugins.ml2.db.get_sg_ids_grouped_by_port',
                        return_value={}) as get_mock:
                plugin.get_ports_from_devices(self.ctx,
                    ['%s%s' % (const.TAP_DEVICE_PREFIX, i)
                     for i in range(ports_to_query)])
                all_call_args = map(lambda x: x[1][1], get_mock.mock_calls)
                last_call_args = all_call_args.pop()
                # all but last should be getting MAX_PORTS_PER_QUERY ports
                self.assertTrue(
                    all(map(lambda x: len(x) == max_ports_per_query,
                            all_call_args))
                )
                remaining = ports_to_query % max_ports_per_query
                if remaining:
                    self.assertEqual(remaining, len(last_call_args))
                # should be broken into ceil(total/MAX_PORTS_PER_QUERY) calls
                self.assertEqual(
                    math.ceil(ports_to_query / float(max_ports_per_query)),
                    get_mock.call_count
                )

    def test_full_uuids_skip_port_id_lookup(self):
        plugin = manager.NeutronManager.get_plugin()
        # when full UUIDs are provided, the _or statement should only
        # have one matching 'IN' critiera for all of the IDs
        with mock.patch('neutron.plugins.ml2.db.or_') as or_mock,\
                mock.patch('sqlalchemy.orm.Session.query') as qmock:
            fmock = qmock.return_value.outerjoin.return_value.filter
            # return no ports to exit the method early since we are mocking
            # the query
            fmock.return_value = []
            plugin.get_ports_from_devices(self.ctx,
                                          [test_base._uuid(),
                                           test_base._uuid()])
            # the or_ function should only have one argument
            or_mock.assert_called_once_with(mock.ANY)


class TestMl2SGServerRpcCallBack(
    Ml2SecurityGroupsTestCase,
    test_sg_rpc.SGServerRpcCallBackTestCase):
    pass

# Copyright (c) 2017 Fujitsu Limited
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

from unittest import mock

from neutron_lib import constants
from neutron_lib.plugins.ml2 import ovs_constants as ovs_consts
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.objects.logapi import logging_resource as log_object
from neutron.services.logapi.common import exceptions as log_exc
from neutron.services.logapi.drivers.openvswitch \
    import ovs_firewall_log as ovsfw_log
from neutron.services.logapi.rpc import agent as agent_rpc
from neutron.tests import base
from neutron.tests import tools

COOKIE_ID = uuidutils.generate_uuid()
PORT_ID = uuidutils.generate_uuid()
PROJECT_ID = uuidutils.generate_uuid()
ACTION = tools.get_random_security_event()
LOG_ID = uuidutils.generate_uuid()
SG_ID = uuidutils.generate_uuid()
REMOTE_SG_ID = uuidutils.generate_uuid()

FakeSGLogInfo = [
    {
        'id': LOG_ID,
        'ports_log': [{'port_id': PORT_ID,
                       'security_group_rules': [
                           {'ethertype': constants.IPv4,
                            'protocol': constants.PROTO_NAME_TCP,
                            'direction': constants.INGRESS_DIRECTION,
                            'port_range_min': 123,
                            'port_range_max': 123,
                            'security_group_id': SG_ID},
                           {'ethertype': constants.IPv4,
                            'protocol': constants.PROTO_NAME_UDP,
                            'direction': constants.EGRESS_DIRECTION,
                            'security_group_id': SG_ID},
                           {'ethertype': constants.IPv6,
                            'protocol': constants.PROTO_NAME_TCP,
                            'remote_group_id': REMOTE_SG_ID,
                            'direction': constants.EGRESS_DIRECTION,
                            'security_group_id': SG_ID}
                       ]}],
        'event': 'ALL',
        'project_id': PROJECT_ID,
    }
]


def set_log_driver_config(ctrl_rate_limit, ctrl_burst_limit):
    cfg.CONF.set_override('rate_limit', ctrl_rate_limit, group='network_log')
    cfg.CONF.set_override('burst_limit', ctrl_burst_limit, group='network_log')


class TestCookie(base.BaseTestCase):
    def setUp(self):
        super(TestCookie, self).setUp()
        self.cookie = ovsfw_log.Cookie(COOKIE_ID, PORT_ID, ACTION, PROJECT_ID)
        self.cookie.log_object_refs = set([LOG_ID])

    def test_add_log_object_refs(self):
        new_log_id = uuidutils.generate_uuid()
        expected = set([LOG_ID, new_log_id])
        self.cookie.add_log_obj_ref(new_log_id)
        self.assertEqual(expected, self.cookie.log_object_refs)

    def test_removed_log_object_ref(self):
        expected = set()
        self.cookie.remove_log_obj_ref(LOG_ID)
        self.assertEqual(expected, self.cookie.log_object_refs)

    def test_is_empty(self):
        self.cookie.remove_log_obj_ref(LOG_ID)
        result = self.cookie.is_empty
        self.assertTrue(result)


class FakeOVSPort(object):
    def __init__(self, name, port, mac):
        self.port_name = name
        self.ofport = port
        self.vif_mac = mac


class TestOVSFirewallLoggingDriver(base.BaseTestCase):
    def setUp(self):
        super(TestOVSFirewallLoggingDriver, self).setUp()
        mock_int_br = mock.Mock()
        mock_int_br.br.dump_flows.return_value = []
        self._mock_initialize_bridge = mock.patch.object(
            ovsfw_log.OVSFirewallLoggingDriver, 'initialize_bridge',
            return_value=mock_int_br)
        self.mock_initialize_bridge = self._mock_initialize_bridge.start()
        self.log_driver = ovsfw_log.OVSFirewallLoggingDriver(mock.Mock())
        resource_rpc_mock = mock.patch.object(
            agent_rpc, 'LoggingApiStub', autospec=True).start()
        self.log_driver.start_logapp = mock.Mock()
        self.log_driver.initialize(resource_rpc_mock)
        self.log_driver.SUPPORTED_LOGGING_TYPES = ['security_group']
        self.mock_bridge = self.log_driver.int_br
        self.mock_bridge.reset_mock()
        self.fake_ovs_port = FakeOVSPort('port', 1, '00:00:00:00:00:00')
        self.mock_bridge.br.get_vif_port_by_id.return_value = \
            self.fake_ovs_port
        log_data = {
            'context': None,
            'name': 'test1',
            'id': LOG_ID,
            'project_id': PROJECT_ID,
            'event': 'ALL',
            'resource_type': 'security_group'
        }
        self.log_resource = log_object.Log(**log_data)

    @property
    def port_ofport(self):
        return self.mock_bridge.br.get_vif_port_by_id.return_value.ofport

    @property
    def port_mac(self):
        return self.mock_bridge.br.get_vif_port_by_id.return_value.vif_mac

    def test_initialize_bridge(self):
        self._mock_initialize_bridge.stop()
        br = self.log_driver.initialize_bridge(self.mock_bridge)
        self.assertEqual(self.mock_bridge.deferred.return_value, br)

    def test_set_controller_rate_limit(self):
        self._mock_initialize_bridge.stop()
        set_log_driver_config(100, 25)
        self.log_driver.initialize_bridge(self.mock_bridge)
        expected_calls = [mock.call.set_controller_rate_limit(100),
                          mock.call.set_controller_burst_limit(25)]
        self.mock_bridge.assert_has_calls(expected_calls)

    def test_generate_cookie(self):
        cookie_id = self.log_driver.generate_cookie(
            PORT_ID, ACTION, LOG_ID, PROJECT_ID)
        cookie = self.log_driver._get_cookie_by_id(cookie_id)
        self.assertIn(cookie, self.log_driver.cookies_table)

    def test__get_cookie_by_id_not_found(self):
        cookie_id = uuidutils.generate_uuid()
        cookie = ovsfw_log.Cookie(cookie_id=uuidutils.generate_uuid(),
                                  port=PORT_ID, action=ACTION,
                                  project=PROJECT_ID)
        self.log_driver.cookies_table = set([cookie])
        self.assertRaises(log_exc.CookieNotFound,
                          self.log_driver._get_cookie_by_id,
                          cookie_id)

    def test_start_log_with_update_or_create_log_event(self):
        context = mock.Mock()
        log_data = {'log_resources': [self.log_resource]}
        self.log_driver.resource_rpc.get_sg_log_info_for_log_resources.\
            return_value = FakeSGLogInfo
        self.log_driver.start_logging(context, **log_data)
        accept_cookie = self.log_driver._get_cookie(PORT_ID, 'ACCEPT')
        drop_cookie = self.log_driver._get_cookie(PORT_ID, 'DROP')
        conj_id = self.log_driver.conj_id_map.get_conj_id(
            SG_ID, REMOTE_SG_ID, constants.EGRESS_DIRECTION, constants.IPv6)
        add_rules = [
            # log ingress tcp port=123
            mock.call(
                actions='controller',
                cookie=accept_cookie.id,
                reg5=self.port_ofport,
                dl_type="0x{:04x}".format(constants.ETHERTYPE_IP),
                nw_proto=constants.PROTO_NUM_TCP,
                priority=77,
                table=ovs_consts.ACCEPTED_INGRESS_TRAFFIC_TABLE,
                tcp_dst='0x007b'),
            # log egress tcp6
            mock.call(
                actions='resubmit(,%d),controller' % (
                    ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE),
                cookie=accept_cookie.id,
                reg5=self.port_ofport,
                dl_type="0x{:04x}".format(constants.ETHERTYPE_IPV6),
                priority=70,
                reg7=conj_id + 1,
                table=ovs_consts.ACCEPTED_EGRESS_TRAFFIC_TABLE),
            # log egress udp
            mock.call(
                actions='resubmit(,%d),controller' % (
                    ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE),
                cookie=accept_cookie.id,
                reg5=self.port_ofport,
                dl_type="0x{:04x}".format(constants.ETHERTYPE_IP),
                nw_proto=constants.PROTO_NUM_UDP,
                priority=77,
                table=ovs_consts.ACCEPTED_EGRESS_TRAFFIC_TABLE,
            ),
            # log drop
            mock.call(
                actions='controller',
                cookie=drop_cookie.id,
                priority=53,
                reg5=self.port_ofport,
                table=ovs_consts.DROPPED_TRAFFIC_TABLE,
            )

        ]
        self.mock_bridge.br.add_flow.assert_has_calls(
            add_rules, any_order=True)

    def test_stop_log_with_delete_log_event(self):
        context = mock.Mock()
        log_data = {'log_resources': [self.log_resource]}
        self.log_driver.resource_rpc.get_sg_log_info_for_log_resources.\
            return_value = FakeSGLogInfo
        self.log_driver.start_logging(context, **log_data)
        accept_cookie = self.log_driver._get_cookie(PORT_ID, 'ACCEPT')
        drop_cookie = self.log_driver._get_cookie(PORT_ID, 'DROP')
        self.mock_bridge.reset_mock()
        self.log_driver.stop_logging(context, **log_data)

        delete_rules = [
            # delete drop flow
            mock.call(
                table=ovs_consts.DROPPED_TRAFFIC_TABLE,
                cookie=drop_cookie.id
            ),
            # delete accept flows
            mock.call(
                table=ovs_consts.ACCEPTED_EGRESS_TRAFFIC_TABLE,
                cookie=accept_cookie.id
            ),
            mock.call(
                table=ovs_consts.ACCEPTED_INGRESS_TRAFFIC_TABLE,
                cookie=accept_cookie.id
            )
        ]

        self.mock_bridge.br.delete_flows.assert_has_calls(
            delete_rules, any_order=True)

    def test_start_log_with_add_port_event(self):
        context = mock.Mock()
        log_data = {'port_id': PORT_ID}
        self.log_driver.resource_rpc.get_sg_log_info_for_port.return_value = \
            [
                {
                    'id': uuidutils.generate_uuid(),
                    'ports_log': [{'port_id': PORT_ID,
                                   'security_group_rules': [
                                       {'ethertype': constants.IPv4,
                                        'protocol': constants.PROTO_NAME_TCP,
                                        'direction':
                                            constants.INGRESS_DIRECTION,
                                        'port_range_min': 123,
                                        'port_range_max': 123,
                                        'security_group_id': 456}]}],
                    'event': 'ACCEPT',
                    'project_id': PROJECT_ID,
                }
            ]
        self.log_driver.start_logging(context, **log_data)
        accept_cookie = self.log_driver._get_cookie(PORT_ID, 'ACCEPT')
        add_rules = [
            # log ingress tcp port=123
            mock.call(
                actions='controller',
                cookie=accept_cookie.id,
                reg5=self.port_ofport,
                dl_type="0x{:04x}".format(constants.ETHERTYPE_IP),
                nw_proto=constants.PROTO_NUM_TCP,
                priority=77,
                table=ovs_consts.ACCEPTED_INGRESS_TRAFFIC_TABLE,
                tcp_dst='0x007b')
        ]
        self.mock_bridge.br.add_flow.assert_has_calls(
            add_rules, any_order=True)

    def test_stop_log_with_delete_port_event(self):

        context = mock.Mock()
        log_data = {'port_id': PORT_ID}
        # add port
        self.log_driver.resource_rpc.get_sg_log_info_for_port.return_value = \
            FakeSGLogInfo
        self.log_driver.start_logging(context, **log_data)
        accept_cookie = self.log_driver._get_cookie(PORT_ID, 'ACCEPT')
        drop_cookie = self.log_driver._get_cookie(PORT_ID, 'DROP')
        self.mock_bridge.reset_mock()
        # delete port
        self.log_driver.stop_logging(
            context, port_id=PORT_ID)

        delete_rules = [
            # delete accept flows
            mock.call(
                table=ovs_consts.ACCEPTED_INGRESS_TRAFFIC_TABLE,
                cookie=accept_cookie.id
            ),
            mock.call(
                table=ovs_consts.ACCEPTED_EGRESS_TRAFFIC_TABLE,
                cookie=accept_cookie.id
            ),
            # delete drop flow
            mock.call(
                table=ovs_consts.DROPPED_TRAFFIC_TABLE,
                cookie=drop_cookie.id
            ),
        ]
        self.mock_bridge.br.delete_flows.assert_has_calls(
            delete_rules, any_order=True)

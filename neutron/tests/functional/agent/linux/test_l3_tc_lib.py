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

from neutron_lib import constants as common_constants
from neutron_lib import exceptions
from oslo_utils import uuidutils

from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
from neutron.agent.linux import l3_tc_lib
from neutron.tests.functional import base as functional_base

RATE_LIMIT = 1024
BURST_LIMIT = 512
DEV_NAME = "test_device"


class TcLibTestCase(functional_base.BaseSudoTestCase):

    def create_tc_wrapper_with_namespace_and_device(self):
        ns_name = uuidutils.generate_uuid()
        namespace = namespaces.Namespace(
            ns_name, None,
            mock.Mock(), False)
        namespace.create()
        self.addCleanup(namespace.delete)
        ip_wrapper = ip_lib.IPWrapper(namespace=ns_name)
        tc_device = ip_wrapper.add_tuntap(DEV_NAME)
        tc_device.link.set_up()
        return l3_tc_lib.FloatingIPTcCommand(
            DEV_NAME,
            namespace=ns_name)

    def test_clear_all_filters(self):
        ip_addr = "2.2.2.2"
        l3_tc = self.create_tc_wrapper_with_namespace_and_device()
        l3_tc.set_ip_rate_limit(common_constants.INGRESS_DIRECTION, ip_addr,
                                RATE_LIMIT, BURST_LIMIT)
        l3_tc.set_ip_rate_limit(common_constants.EGRESS_DIRECTION, ip_addr,
                                RATE_LIMIT, BURST_LIMIT)

        l3_tc.clear_all_filters(common_constants.INGRESS_DIRECTION)
        self.assertRaises(exceptions.FilterIDForIPNotFound,
                          l3_tc.get_filter_id_for_ip,
                          common_constants.INGRESS_DIRECTION,
                          ip_addr)

        l3_tc.clear_all_filters(common_constants.EGRESS_DIRECTION)
        self.assertRaises(exceptions.FilterIDForIPNotFound,
                          l3_tc.get_filter_id_for_ip,
                          common_constants.EGRESS_DIRECTION,
                          ip_addr)

    def test_get_filter_id_for_ip(self):
        ip_addr = "3.3.3.3"
        l3_tc = self.create_tc_wrapper_with_namespace_and_device()
        l3_tc.set_ip_rate_limit(common_constants.INGRESS_DIRECTION, ip_addr,
                                RATE_LIMIT, BURST_LIMIT)
        l3_tc.set_ip_rate_limit(common_constants.EGRESS_DIRECTION, ip_addr,
                                RATE_LIMIT, BURST_LIMIT)

        self.assertIsNotNone(
            l3_tc.get_filter_id_for_ip(common_constants.INGRESS_DIRECTION,
                                       ip_addr))
        self.assertIsNotNone(
            l3_tc.get_filter_id_for_ip(common_constants.EGRESS_DIRECTION,
                                       ip_addr))

        # testing: IP filter does not exist
        self.assertRaises(exceptions.FilterIDForIPNotFound,
                          l3_tc.get_filter_id_for_ip,
                          common_constants.EGRESS_DIRECTION,
                          '33.33.33.33')

    def test_get_existing_filter_ids(self):
        ip_addr = "4.4.4.4"
        l3_tc = self.create_tc_wrapper_with_namespace_and_device()
        l3_tc.set_ip_rate_limit(common_constants.INGRESS_DIRECTION, ip_addr,
                                RATE_LIMIT, BURST_LIMIT)
        l3_tc.set_ip_rate_limit(common_constants.EGRESS_DIRECTION, ip_addr,
                                RATE_LIMIT, BURST_LIMIT)

        filter_ids = l3_tc.get_existing_filter_ids(
            common_constants.INGRESS_DIRECTION)
        self.assertNotEqual(0, len(filter_ids))
        filter_ids = l3_tc.get_existing_filter_ids(
            common_constants.EGRESS_DIRECTION)
        self.assertNotEqual(0, len(filter_ids))

    def test_delete_filter_ids(self):
        ip_addr1 = "5.5.5.5"
        ip_addr2 = "6.6.6.6"
        l3_tc = self.create_tc_wrapper_with_namespace_and_device()
        l3_tc.set_ip_rate_limit(common_constants.INGRESS_DIRECTION, ip_addr1,
                                RATE_LIMIT, BURST_LIMIT)
        l3_tc.set_ip_rate_limit(common_constants.INGRESS_DIRECTION, ip_addr2,
                                RATE_LIMIT, BURST_LIMIT)

        filter_ids = l3_tc.get_existing_filter_ids(
            common_constants.INGRESS_DIRECTION)
        self.assertEqual(2, len(filter_ids))
        l3_tc.delete_filter_ids(common_constants.INGRESS_DIRECTION,
                                filter_ids)
        filter_ids = l3_tc.get_existing_filter_ids(
            common_constants.INGRESS_DIRECTION)
        self.assertEqual(0, len(filter_ids))

    def test_set_ip_rate_limit(self):
        ip_addr = "7.7.7.7"
        l3_tc = self.create_tc_wrapper_with_namespace_and_device()
        # Set it multiple times
        l3_tc.set_ip_rate_limit(common_constants.INGRESS_DIRECTION, ip_addr,
                                RATE_LIMIT, BURST_LIMIT)
        l3_tc.set_ip_rate_limit(common_constants.INGRESS_DIRECTION, ip_addr,
                                RATE_LIMIT, BURST_LIMIT)
        l3_tc.set_ip_rate_limit(common_constants.INGRESS_DIRECTION, ip_addr,
                                RATE_LIMIT, BURST_LIMIT)
        # Get only one and no exception
        filter_id = l3_tc.get_filter_id_for_ip(
            common_constants.INGRESS_DIRECTION,
            ip_addr)
        self.assertIsNotNone(filter_id)

    def test_clear_ip_rate_limit(self):
        ip_addr = "8.8.8.8"
        l3_tc = self.create_tc_wrapper_with_namespace_and_device()
        l3_tc.set_ip_rate_limit(common_constants.INGRESS_DIRECTION,
                                ip_addr,
                                RATE_LIMIT, BURST_LIMIT)
        filter_id = l3_tc.get_filter_id_for_ip(
            common_constants.INGRESS_DIRECTION,
            ip_addr)
        self.assertIsNotNone(filter_id)
        l3_tc.clear_ip_rate_limit(
            common_constants.INGRESS_DIRECTION,
            ip_addr)
        self.assertRaises(exceptions.FilterIDForIPNotFound,
                          l3_tc.get_filter_id_for_ip,
                          common_constants.INGRESS_DIRECTION,
                          ip_addr)

        # testing: IP filter does not exist
        l3_tc.clear_ip_rate_limit(
            common_constants.INGRESS_DIRECTION,
            "88.88.88.88")

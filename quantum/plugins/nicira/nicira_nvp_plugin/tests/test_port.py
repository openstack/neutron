# Copyright 2012 Nicira Networks, Inc.
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
# @author: Somik Behera, Nicira Networks, Inc.

import json
import logging
import os
import unittest

from quantum.common import exceptions as exception
from nicira_nvp_plugin.QuantumPlugin import NvpPlugin
from nicira_nvp_plugin import NvpApiClient
from nicira_nvp_plugin import nvplib

logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger("test_port")


class NvpTests(unittest.TestCase):
    def setUp(self):
        self.quantum = NvpPlugin()
        self.BRIDGE_TZ_UUID = self._create_tz("bridge")
        self.networks = []
        self.ports = []
        self.transport_nodes = []
        self.cis_uuids = []

    def tearDown(self):
        self._delete_tz(self.BRIDGE_TZ_UUID)

        for (net_id, p) in self.ports:
            self.quantum.unplug_interface("quantum-test-tenant", net_id, p)
            self.quantum.delete_port("quantum-test-tenant", net_id, p)
        for n in self.networks:
            self.quantum.delete_network("quantum-test-tenant", n)
        for t in self.transport_nodes:
            nvplib.do_single_request("DELETE", "/ws.v1/transport-node/%s" % t,
                                     controller=self.quantum.controller)
        for c in self.cis_uuids:
            nvplib.do_single_request("DELETE",
                "/ws.v1/cluster-interconnect-service/%s" % c,
                controller=self.quantum.controller)

    def _create_tz(self, name):
        post_uri = "/ws.v1/transport-zone"
        body = {"display_name": name,
                "tags": [{"tag": "plugin-test"}]}
        try:
            resp_obj = self.quantum.api_client.request("POST",
              post_uri, json.dumps(body))
        except NvpApiClient.NvpApiException as e:
            LOG.error("Unknown API Error: %s" % str(e))
            raise exception.QuantumException()
        return json.loads(resp_obj)["uuid"]

    def _delete_tz(self, uuid):
        post_uri = "/ws.v1/transport-zone/%s" % uuid
        try:
            resp_obj = self.quantum.api_client.request("DELETE", post_uri)
        except NvpApiClient.NvpApiException as e:
            LOG.error("Unknown API Error: %s" % str(e))
            raise exception.QuantumException()

    def test_create_and_delete_lots_of_ports(self):
        resp = self.quantum.create_custom_network(
            "quantum-test-tenant", "quantum-Private-TenantA",
            self.BRIDGE_TZ_UUID, self.quantum.controller)
        net_id = resp["net-id"]

        nports = 250

        ids = []
        for i in xrange(0, nports):
            resp = self.quantum.create_port("quantum-test-tenant", net_id,
                                            "ACTIVE")
            port_id = resp["port-id"]
            ids.append(port_id)

        # Test that we get the correct number of ports back
        ports = self.quantum.get_all_ports("quantum-test-tenant", net_id)
        self.assertTrue(len(ports) == nports)

        # Verify that each lswitch has matching tags
        net = nvplib.get_network(self.quantum.controller, net_id)
        tags = []
        net_tags = [t["tag"] for t in net["tags"]]
        if len(tags) == 0:
            tags = net_tags
        else:
            for t in net_tags:
                self.assertTrue(t in tags)

        for port_id in ids:
            resp = self.quantum.delete_port("quantum-test-tenant", net_id,
                                            port_id)
            try:
                self.quantum.get_port_details("quantum-test-tenant", net_id,
                                              port_id)
            except exception.PortNotFound:
                continue
            # Shouldn't be reached
            self.assertFalse(True)

        self.quantum.delete_network("quantum-test-tenant", net_id)

    def test_create_and_delete_port(self):
        resp = self.quantum.create_custom_network(
            "quantum-test-tenant", "quantum-Private-TenantA",
            self.BRIDGE_TZ_UUID, self.quantum.controller)
        net_id = resp["net-id"]

        resp = self.quantum.create_port("quantum-test-tenant", net_id,
                                        "ACTIVE")
        port_id = resp["port-id"]
        resp = self.quantum.delete_port("quantum-test-tenant", net_id, port_id)
        self.quantum.delete_network("quantum-test-tenant", net_id)

    def test_create_and_delete_port_with_portsec(self):
        resp = self.quantum.create_custom_network(
            "quantum-test-tenant", "quantum-Private-TenantA",
            self.BRIDGE_TZ_UUID, self.quantum.controller)
        net_id = resp["net-id"]

        params = {}
        params["NICIRA:allowed_address_pairs"] = [
          {
             "ip_address": "172.168.17.5",
             "mac_address": "10:9a:dd:61:4e:89"
            },
            {
             "ip_address": "172.168.17.6",
             "mac_address": "10:9a:dd:61:4e:88"
            }
        ]
        resp = self.quantum.create_port("quantum-test-tenant", net_id,
            "ACTIVE", **params)
        port_id = resp["port-id"]
        resp = self.quantum.delete_port("quantum-test-tenant", net_id, port_id)
        self.quantum.delete_network("quantum-test-tenant", net_id)
        self.assertTrue(True)

    def test_create_update_and_delete_port(self):
        resp = self.quantum.create_custom_network(
            "quantum-test-tenant", "quantum-Private-TenantA",
            self.BRIDGE_TZ_UUID, self.quantum.controller)
        net_id = resp["net-id"]

        resp = self.quantum.create_port("quantum-test-tenant", net_id,
                                        "ACTIVE")
        port_id = resp["port-id"]
        resp = self.quantum.get_port_details("quantum-test-tenant", net_id,
                                             port_id)
        resp = self.quantum.delete_port("quantum-test-tenant", net_id,
                                        port_id)
        self.quantum.delete_network("quantum-test-tenant",
                                    net_id)
        self.assertTrue(True)

    def test_create_plug_unplug_iface(self):
        resp = self.quantum.create_custom_network(
            "quantum-test-tenant", "quantum-Private-TenantA",
            self.BRIDGE_TZ_UUID, self.quantum.controller)
        net_id = resp["net-id"]

        resp = self.quantum.create_port("quantum-test-tenant", net_id,
                                        "ACTIVE")
        port_id = resp["port-id"]
        resp = self.quantum.get_port_details("quantum-test-tenant", net_id,
                                             port_id)
        old_vic = resp["attachment"]
        self.assertTrue(old_vic == "None")
        self.quantum.plug_interface("quantum-test-tenant", net_id, port_id,
            "nova-instance-test-%s" % os.getpid())
        resp = self.quantum.get_port_details("quantum-test-tenant", net_id,
                                             port_id)
        new_vic = resp["attachment"]

        self.assertTrue(old_vic != new_vic)
        self.quantum.unplug_interface("quantum-test-tenant", net_id, port_id)
        resp = self.quantum.get_port_details("quantum-test-tenant", net_id,
                                             port_id)
        new_vic = resp["attachment"]
        self.assertTrue(old_vic == new_vic)
        resp = self.quantum.delete_port("quantum-test-tenant", net_id, port_id)
        self.quantum.delete_network("quantum-test-tenant", net_id)
        self.assertTrue(True)

    def test_create_multi_port_attachment(self):
        resp = self.quantum.create_custom_network(
            "quantum-test-tenant", "quantum-Private-TenantA",
            self.BRIDGE_TZ_UUID, self.quantum.controller)
        net_id = resp["net-id"]

        resp = self.quantum.create_port("quantum-test-tenant", net_id,
                                        "ACTIVE")
        port_id1 = resp["port-id"]
        resp = self.quantum.get_port_details("quantum-test-tenant", net_id,
                                             port_id1)
        old_vic = resp["attachment"]
        self.assertTrue(old_vic == "None")

        self.quantum.plug_interface("quantum-test-tenant", net_id, port_id1,
            "nova-instance-test-%s" % os.getpid())
        resp = self.quantum.get_port_details("quantum-test-tenant", net_id,
                                             port_id1)
        new_vic = resp["attachment"]
        self.assertTrue(old_vic != new_vic)

        resp = self.quantum.create_port("quantum-test-tenant", net_id,
                                        "ACTIVE")
        port_id2 = resp["port-id"]
        resp = self.quantum.get_port_details("quantum-test-tenant", net_id,
                                             port_id2)
        old_vic2 = resp["attachment"]
        self.assertTrue(old_vic2 == "None")

        self.quantum.plug_interface("quantum-test-tenant", net_id, port_id2,
            "nova-instance-test2-%s" % os.getpid())
        resp = self.quantum.get_port_details("quantum-test-tenant", net_id,
                                             port_id2)
        new_vic = resp["attachment"]
        self.assertTrue(old_vic2 != new_vic)

        resp = self.quantum.get_all_ports("quantum-test-tenant", net_id)

        resp = self.quantum.get_network_details("quantum-test-tenant", net_id)

        resp = self.quantum.delete_port("quantum-test-tenant", net_id,
                                        port_id1)
        resp = self.quantum.delete_port("quantum-test-tenant", net_id,
                                        port_id2)
        self.quantum.delete_network("quantum-test-tenant", net_id)
        self.assertTrue(True)

    def test_negative_get_all_ports(self):
        try:
            self.quantum.get_all_ports("quantum-test-tenant", "xxx-no-net-id")
        except exception.NetworkNotFound:
            self.assertTrue(True)
            return

        self.assertTrue(False)

    def test_negative_create_port1(self):
        try:
            self.quantum.create_port("quantum-test-tenant", "xxx-no-net-id",
              "ACTIVE")
        except exception.NetworkNotFound:
            self.assertTrue(True)
            return

        self.assertTrue(False)

    def test_negative_create_port2(self):
        resp1 = self.quantum.create_network("quantum-test-tenant",
            "quantum-Private-TenantB")
        try:
            self.quantum.create_port("quantum-test-tenant", resp1["net-id"],
                "INVALID")
        except exception.StateInvalid:
            self.assertTrue(True)
            self.quantum.delete_network("quantum-test-tenant", resp1["net-id"])
            return

        self.quantum.delete_network("quantum-test-tenant", resp1["net-id"])
        self.assertTrue(False)

    def test_negative_update_port1(self):
        resp1 = self.quantum.create_network("quantum-test-tenant",
            "quantum-Private-TenantB")
        try:
            self.quantum.update_port("quantum-test-tenant", resp1["net-id"],
                "port_id_fake", state="ACTIVE")
        except exception.PortNotFound:
            self.assertTrue(True)
            self.quantum.delete_network("quantum-test-tenant", resp1["net-id"])
            return

        self.assertTrue(False)

    def test_negative_update_port2(self):
        resp1 = self.quantum.create_network("quantum-test-tenant",
            "quantum-Private-TenantB")
        try:
            self.quantum.update_port("quantum-test-tenant", resp1["net-id"],
                "port_id_fake", state="INVALID")
        except exception.StateInvalid:
            self.assertTrue(True)
            self.quantum.delete_network("quantum-test-tenant", resp1["net-id"])
            return

        self.assertTrue(False)

    def test_negative_update_port3(self):
        resp1 = self.quantum.create_network("quantum-test-tenant",
            "quantum-Private-TenantB")
        try:
            self.quantum.update_port("quantum-test-tenant", resp1["net-id"],
                "port_id_fake", state="ACTIVE")
        except exception.PortNotFound:
            self.assertTrue(True)
            self.quantum.delete_network("quantum-test-tenant", resp1["net-id"])
            return

        self.quantum.delete_network("quantum-test-tenant", resp1["net-id"])
        self.assertTrue(False)

    def test_negative_delete_port1(self):
        resp1 = self.quantum.create_network("quantum-test-tenant",
            "quantum-Private-TenantB")
        try:
            self.quantum.delete_port("quantum-test-tenant", resp1["net-id"],
                "port_id_fake")
        except exception.PortNotFound:
            self.assertTrue(True)
            self.quantum.delete_network("quantum-test-tenant", resp1["net-id"])
            return

        self.assertTrue(False)

    def test_negative_delete_port2(self):
        resp1 = self.quantum.create_network("quantum-test-tenant",
            "quantum-Private-TenantB")
        try:
            self.quantum.delete_port("quantum-test-tenant", resp1["net-id"],
                "port_id_fake")
        except exception.PortNotFound:
            self.assertTrue(True)
            self.quantum.delete_network("quantum-test-tenant", resp1["net-id"])
            return

        self.quantum.delete_network("quantum-test-tenant", resp1["net-id"])
        self.assertTrue(False)

    def test_negative_get_port_details(self):
        resp1 = self.quantum.create_network("quantum-test-tenant",
            "quantum-Private-TenantB")
        try:
            self.quantum.get_port_details("quantum-test-tenant",
                                          resp1["net-id"],
                "port_id_fake")
        except exception.PortNotFound:
            self.assertTrue(True)
            self.quantum.delete_network("quantum-test-tenant",
                                        resp1["net-id"])
            return

        self.quantum.delete_network("quantum-test-tenant", resp1["net-id"])
        self.assertTrue(False)

    def test_negative_plug_interface(self):
        resp1 = self.quantum.create_network("quantum-test-tenant",
            "quantum-Private-TenantB")
        try:
            self.quantum.plug_interface("quantum-test-tenant",
                                        resp1["net-id"],
                                        "port_id_fake", "iface_id_fake")
        except exception.PortNotFound:
            self.assertTrue(True)
            self.quantum.delete_network("quantum-test-tenant",
                                        resp1["net-id"])
            return

        self.assertTrue(False)

    def test_negative_unplug_interface(self):
        resp1 = self.quantum.create_network("quantum-test-tenant",
            "quantum-Private-TenantB")
        try:
            self.quantum.unplug_interface("quantum-test-tenant",
                                          resp1["net-id"], "port_id_fake")
        except exception.PortNotFound:
            self.assertTrue(True)
            self.quantum.delete_network("quantum-test-tenant",
                                        resp1["net-id"])
            return

        self.assertTrue(False)

    def test_get_port_status_invalid_lswitch(self):
        try:
            nvplib.get_port_status(self.quantum.controller,
                                   "invalid-lswitch",
                                   "invalid-port")
        except exception.NetworkNotFound:
            return
        # Shouldn't be reached
        self.assertTrue(False)

    def test_get_port_status_invalid_port(self):
        resp = self.quantum.create_custom_network("quantum-test-tenant",
            "quantum-Private-TenantA", self.BRIDGE_TZ_UUID,
            self.quantum.controller)
        net_id = resp["net-id"]
        self.networks.append(net_id)

        try:
            nvplib.get_port_status(self.quantum.controller, net_id,
                                   "invalid-port")
        except exception.PortNotFound:
            return
        # Shouldn't be reached
        self.assertTrue(False)

    def test_get_port_status_returns_the_right_stuff(self):
        resp = self.quantum.create_custom_network("quantum-test-tenant",
            "quantum-Private-TenantA", self.BRIDGE_TZ_UUID,
            self.quantum.controller)
        net_id = resp["net-id"]
        self.networks.append(net_id)
        resp = self.quantum.create_port("quantum-test-tenant", net_id,
                                        "ACTIVE")
        port_id = resp["port-id"]
        self.ports.append((net_id, port_id))
        res = nvplib.get_port_status(self.quantum.controller, net_id, port_id)
        self.assertTrue(res in ['UP', 'DOWN', 'PROVISIONING'])

    def test_get_port_stats_invalid_lswitch(self):
        try:
            nvplib.get_port_stats(self.quantum.controller,
                                  "invalid-lswitch",
                                  "invalid-port")
        except exception.NetworkNotFound:
            return
        # Shouldn't be reached
        self.assertTrue(False)

    def test_get_port_stats_invalid_port(self):
        resp = self.quantum.create_custom_network("quantum-test-tenant",
            "quantum-Private-TenantA", self.BRIDGE_TZ_UUID,
            self.quantum.controller)
        net_id = resp["net-id"]
        self.networks.append(net_id)

        try:
            nvplib.get_port_stats(self.quantum.controller, net_id,
                                  "invalid-port")
        except exception.PortNotFound:
            return
        # Shouldn't be reached
        self.assertTrue(False)

    def test_get_port_stats_returns_the_right_stuff(self):
        resp = self.quantum.create_custom_network("quantum-test-tenant",
            "quantum-Private-TenantA", self.BRIDGE_TZ_UUID,
            self.quantum.controller)
        net_id = resp["net-id"]
        self.networks.append(net_id)
        resp = self.quantum.create_port("quantum-test-tenant", net_id,
                                        "ACTIVE")
        port_id = resp["port-id"]
        self.ports.append((net_id, port_id))
        res = nvplib.get_port_stats(self.quantum.controller, net_id, port_id)
        self.assertTrue("tx_errors" in res)
        self.assertTrue("tx_bytes" in res)
        self.assertTrue("tx_packets" in res)
        self.assertTrue("rx_errors" in res)
        self.assertTrue("rx_bytes" in res)
        self.assertTrue("rx_packets" in res)

    def test_port_filters_by_attachment(self):
        resp = self.quantum.create_custom_network("quantum-test-tenant",
            "quantum-Private-TenantA", self.BRIDGE_TZ_UUID,
            self.quantum.controller)
        net_id = resp["net-id"]
        self.networks.append(net_id)

        resp = self.quantum.create_port("quantum-test-tenant", net_id,
                                        "ACTIVE")
        port_id = resp["port-id"]
        port_id1 = port_id
        self.ports.append((net_id, port_id))
        self.quantum.plug_interface("quantum-test-tenant", net_id, port_id,
            "attachment1")

        resp = self.quantum.create_port("quantum-test-tenant", net_id,
                                        "ACTIVE")
        port_id = resp["port-id"]
        port_id2 = port_id
        self.ports.append((net_id, port_id))
        self.quantum.plug_interface("quantum-test-tenant", net_id, port_id,
            "attachment2")

        # Make sure we get all the ports that we created back
        ports = self.quantum.get_all_ports("quantum-test-tenant", net_id)
        self.assertTrue(len(ports) == 2)

        # Make sure we only get the filtered ones back
        ports = self.quantum.get_all_ports("quantum-test-tenant", net_id,
            filter_opts={"attachment": "attachment2"})
        self.assertTrue(len(ports) == 1)
        self.assertTrue(ports[0]["port-id"] == port_id2)

        # Make sure we don't get any back with an invalid filter
        ports = self.quantum.get_all_ports("quantum-test-tenant", net_id,
            filter_opts={"attachment": "invalidattachment"})
        self.assertTrue(len(ports) == 0)

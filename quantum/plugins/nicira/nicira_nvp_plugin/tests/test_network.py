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
# @author: Brad Hall, Nicira Networks, Inc.

import json
import logging
import os
import unittest

from quantum.common import exceptions as exception
from quantum.plugins.nicira.nicira_nvp_plugin.QuantumPlugin import NvpPlugin
from quantum.plugins.nicira.nicira_nvp_plugin import (
    NvpApiClient,
    nvplib,
    )


logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger("test_network")


class NvpTests(unittest.TestCase):
    def setUp(self):
        self.quantum = NvpPlugin()
        self.BRIDGE_TZ_UUID = self._create_tz("bridge")
        self.DEFAULT_TZ_UUID = self._create_tz("default")

        self.nets = []
        self.ports = []

    def tearDown(self):
        self._delete_tz(self.BRIDGE_TZ_UUID)
        self._delete_tz(self.DEFAULT_TZ_UUID)

        for tenant, net, port in self.ports:
            self.quantum.delete_port(tenant, net, port)
        for tenant, net in self.nets:
            self.quantum.delete_network(tenant, net)

    def _create_tz(self, name):
        post_uri = "/ws.v1/transport-zone"
        body = {"display_name": name,
                "tags": [{"tag": "plugin-test"}]}
        try:
            resp_obj = self.quantum.api_client.request("POST",
              post_uri, json.dumps(body))
        except NvpApiClient.NvpApiException as e:
            print("Unknown API Error: %s" % str(e))
            raise exception.QuantumException()
        return json.loads(resp_obj)["uuid"]

    def _delete_tz(self, uuid):
        post_uri = "/ws.v1/transport-zone/%s" % uuid
        try:
            resp_obj = self.quantum.api_client.request("DELETE", post_uri)
        except NvpApiClient.NvpApiException as e:
            LOG.error("Unknown API Error: %s" % str(e))
            raise exception.QuantumException()

    def test_create_multi_networks(self):

        resp = self.quantum.create_custom_network(
            "quantum-test-tenant", "quantum-Private-TenantA",
            self.BRIDGE_TZ_UUID, self.quantum.controller)
        resp1 = self.quantum.create_network("quantum-test-tenant",
                                            "quantum-Private-TenantB")
        resp2 = self.quantum.create_network("quantum-test-tenant",
                                            "quantum-Private-TenantC")
        resp3 = self.quantum.create_network("quantum-test-tenant",
                                            "quantum-Private-TenantD")
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

        resp = self.quantum.get_all_networks("quantum-test-tenant")

        resp = self.quantum.delete_port("quantum-test-tenant", net_id,
                                        port_id1)
        resp = self.quantum.delete_port("quantum-test-tenant", net_id,
                                        port_id2)
        self.quantum.delete_network("quantum-test-tenant", net_id)
        self.quantum.delete_network("quantum-test-tenant", resp1["net-id"])
        self.quantum.delete_network("quantum-test-tenant", resp2["net-id"])
        self.quantum.delete_network("quantum-test-tenant", resp3["net-id"])

    def test_update_network(self):
        resp = self.quantum.create_network("quantum-test-tenant",
            "quantum-Private-TenantA")
        net_id = resp["net-id"]
        try:
            resp = self.quantum.update_network("quantum-test-tenant", net_id,
                                               name="new-name")
        except exception.NetworkNotFound:
            self.assertTrue(False)

        self.assertTrue(resp["net-name"] == "new-name")

    def test_negative_delete_networks(self):
        try:
            self.quantum.delete_network("quantum-test-tenant", "xxx-no-net-id")
        except exception.NetworkNotFound:
            self.assertTrue(True)

    def test_negative_get_network_details(self):
        try:
            self.quantum.get_network_details("quantum-test-tenant",
                                             "xxx-no-net-id")
        except exception.NetworkNotFound:
            self.assertTrue(True)

    def test_negative_update_network(self):
        try:
            self.quantum.update_network("quantum-test-tenant", "xxx-no-net-id",
                                        name="new-name")
        except exception.NetworkNotFound:
            self.assertTrue(True)

    def test_get_all_networks(self):
        networks = self.quantum.get_all_networks("quantum-test-tenant")
        num_nets = len(networks)

        # Make sure we only get back networks with the specified tenant_id
        unique_tid = "tenant-%s" % os.getpid()
        # Add a network that we shouldn't get back
        resp = self.quantum.create_custom_network(
            "another_tid", "another_tid_network",
            self.BRIDGE_TZ_UUID, self.quantum.controller)
        net_id = resp["net-id"]
        self.nets.append(("another_tid", net_id))
        # Add 3 networks that we should get back
        for i in [1, 2, 3]:
            resp = self.quantum.create_custom_network(
                unique_tid, "net-%s" % str(i),
                self.BRIDGE_TZ_UUID, self.quantum.controller)
            net_id = resp["net-id"]
            self.nets.append((unique_tid, net_id))
        networks = self.quantum.get_all_networks(unique_tid)
        self.assertTrue(len(networks) == 3)

    def test_delete_nonexistent_network(self):
        try:
            nvplib.delete_network(self.quantum.controller,
                                  "my-non-existent-network")
        except exception.NetworkNotFound:
            return
        # shouldn't be reached
        self.assertTrue(False)

    def test_query_networks(self):
        resp = self.quantum.create_custom_network(
            "quantum-test-tenant", "quantum-Private-TenantA",
            self.BRIDGE_TZ_UUID, self.quantum.controller)
        net_id = resp["net-id"]
        self.nets.append(("quantum-test-tenant", net_id))
        nets = nvplib.query_networks(self.quantum.controller,
                                     "quantum-test-tenant")

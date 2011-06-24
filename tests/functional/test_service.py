# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Citrix Systems
# Copyright 2011 Nicira Networks
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

import gettext
import simplejson
import sys
import unittest

gettext.install('quantum', unicode=1)

from miniclient import MiniClient
from quantum.common.wsgi import Serializer

HOST = '127.0.0.1'
PORT = 9696
USE_SSL = False

TENANT_ID = 'totore'
FORMAT = "json"

test_network1_data = \
    {'network': {'network-name': 'test1'}}
test_network2_data = \
    {'network': {'network-name': 'test2'}}


def print_response(res):
    content = res.read()
    print "Status: %s" % res.status
    print "Content: %s" % content
    return content


class QuantumTest(unittest.TestCase):
    def setUp(self):
        self.client = MiniClient(HOST, PORT, USE_SSL)

    def create_network(self, data):
        content_type = "application/" + FORMAT
        body = Serializer().serialize(data, content_type)
        res = self.client.do_request(TENANT_ID, 'POST', "/networks." + FORMAT,
          body=body)
        self.assertEqual(res.status, 200, "bad response: %s" % res.read())

    def test_listNetworks(self):
        self.create_network(test_network1_data)
        self.create_network(test_network2_data)
        res = self.client.do_request(TENANT_ID, 'GET', "/networks." + FORMAT)
        self.assertEqual(res.status, 200, "bad response: %s" % res.read())

    def test_createNetwork(self):
        self.create_network(test_network1_data)

    def test_createPort(self):
        self.create_network(test_network1_data)
        res = self.client.do_request(TENANT_ID, 'GET', "/networks." + FORMAT)
        resdict = simplejson.loads(res.read())
        for n in resdict["networks"]:
            net_id = n["id"]

            # Step 1 - List Ports for network (should not find any)
            res = self.client.do_request(TENANT_ID, 'GET',
              "/networks/%s/ports.%s" % (net_id, FORMAT))
            self.assertEqual(res.status, 200, "Bad response: %s" % res.read())
            output = res.read()
            self.assertTrue(len(output) == 0,
              "Found unexpected ports: %s" % output)

            # Step 2 - Create Port for network
            res = self.client.do_request(TENANT_ID, 'POST',
              "/networks/%s/ports.%s" % (net_id, FORMAT))
            self.assertEqual(res.status, 200, "Bad response: %s" % output)

            # Step 3 - List Ports for network (again); should find one
            res = self.client.do_request(TENANT_ID, 'GET',
              "/networks/%s/ports.%s" % (net_id, FORMAT))
            output = res.read()
            self.assertEqual(res.status, 200, "Bad response: %s" % output)
            resdict = simplejson.loads(output)
            ids = []
            for p in resdict["ports"]:
                ids.append(p["id"])
            self.assertTrue(len(ids) == 1,
              "Didn't find expected # of ports (1): %s" % ids)

    def test_renameNetwork(self):
        self.create_network(test_network1_data)
        res = self.client.do_request(TENANT_ID, 'GET', "/networks." + FORMAT)
        resdict = simplejson.loads(res.read())
        net_id = resdict["networks"][0]["id"]

        data = test_network1_data.copy()
        data['network']['network-name'] = 'test_renamed'
        content_type = "application/" + FORMAT
        body = Serializer().serialize(data, content_type)
        res = self.client.do_request(TENANT_ID, 'PUT',
          "/networks/%s.%s" % (net_id, FORMAT), body=body)
        resdict = simplejson.loads(res.read())
        self.assertTrue(resdict["networks"]["network"]["id"] == net_id,
          "Network_rename: renamed network has a different uuid")
        self.assertTrue(
            resdict["networks"]["network"]["name"] == "test_renamed",
            "Network rename didn't take effect")

    def delete_networks(self):
        # Remove all the networks created on the tenant
        res = self.client.do_request(TENANT_ID, 'GET', "/networks." + FORMAT)
        resdict = simplejson.loads(res.read())
        for n in resdict["networks"]:
            net_id = n["id"]
            res = self.client.do_request(TENANT_ID, 'DELETE',
              "/networks/" + net_id + "." + FORMAT)
            self.assertEqual(res.status, 202)

    def tearDown(self):
        self.delete_networks()

# Standard boilerplate to call the main() function.
if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(QuantumTest)
    unittest.TextTestRunner(verbosity=2).run(suite)

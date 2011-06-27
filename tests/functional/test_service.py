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
import json
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

    def create_network(self, data, tenant_id=TENANT_ID):
        content_type = "application/" + FORMAT
        body = Serializer().serialize(data, content_type)
        res = self.client.do_request(tenant_id, 'POST', "/networks." + FORMAT,
          body=body)
        self.assertEqual(res.status, 200, "bad response: %s" % res.read())

    def test_listNetworks(self):
        self.create_network(test_network1_data)
        self.create_network(test_network2_data)
        res = self.client.do_request(TENANT_ID, 'GET', "/networks." + FORMAT)
        self.assertEqual(res.status, 200, "bad response: %s" % res.read())

    def test_getNonexistentNetwork(self):
        # TODO(bgh): parse exception and make sure it is NetworkNotFound
        try:
            res = self.client.do_request(TENANT_ID, 'GET',
              "/networks/%s.%s" % ("8675309", "xml"))
            self.assertEqual(res.status, 400)
        except Exception, e:
            print "Caught exception: %s" % (str(e))

    def test_deleteNonexistentNetwork(self):
        # TODO(bgh): parse exception and make sure it is NetworkNotFound
        try:
            res = self.client.do_request(TENANT_ID, 'DELETE',
              "/networks/%s.%s" % ("8675309", "xml"))
            self.assertEqual(res.status, 400)
        except Exception, e:
            print "Caught exception: %s" % (str(e))

    def test_createNetwork(self):
        self.create_network(test_network1_data)

    def test_createPort(self):
        self.create_network(test_network1_data)
        res = self.client.do_request(TENANT_ID, 'GET', "/networks." + FORMAT)
        resdict = json.loads(res.read())
        for n in resdict["networks"]:
            net_id = n["id"]

            # Step 1 - List Ports for network (should not find any)
            res = self.client.do_request(TENANT_ID, 'GET',
              "/networks/%s/ports.%s" % (net_id, FORMAT))
            output = res.read()
            self.assertEqual(res.status, 200, "Bad response: %s" % output)
            if len(output) > 0:
                resdict = json.loads(output)
                self.assertTrue(len(resdict["ports"]) == 0,
                  "Found unexpected ports: %s" % output)
            else:
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
            resdict = json.loads(output)
            ids = []
            for p in resdict["ports"]:
                ids.append(p["id"])
            self.assertTrue(len(ids) == 1,
              "Didn't find expected # of ports (1): %s" % ids)

    def test_getAttachment(self):
        self.create_network(test_network1_data)
        res = self.client.do_request(TENANT_ID, 'GET', "/networks." + FORMAT)
        resdict = json.loads(res.read())
        for n in resdict["networks"]:
            net_id = n["id"]

            # Step 1 - Create Port for network and attempt to get the
            # attachment (even though there isn't one)
            res = self.client.do_request(TENANT_ID, 'POST',
              "/networks/%s/ports.%s" % (net_id, FORMAT))
            output = res.read()
            self.assertEqual(res.status, 200, "Bad response: %s" % output)
            resdict = json.loads(output)
            port_id = resdict["ports"]["port"]["id"]

            res = self.client.do_request(TENANT_ID, 'GET',
              "/networks/%s/ports/%s/attachment.%s" % (net_id, port_id,
                FORMAT))
            output = res.read()
            self.assertEqual(res.status, 200, "Bad response: %s" % output)

            # Step 2 - Add an attachment
            data = {'port': {'attachment-id': 'fudd'}}
            content_type = "application/" + FORMAT
            body = Serializer().serialize(data, content_type)
            res = self.client.do_request(TENANT_ID, 'PUT',
              "/networks/%s/ports/%s/attachment.%s" % (net_id, port_id,
                FORMAT), body=body)
            output = res.read()
            self.assertEqual(res.status, 202, "Bad response: %s" % output)

            # Step 3 - Fetch the attachment
            res = self.client.do_request(TENANT_ID, 'GET',
              "/networks/%s/ports/%s/attachment.%s" % (net_id, port_id,
                FORMAT))
            output = res.read()
            self.assertEqual(res.status, 200, "Bad response: %s" % output)
            resdict = json.loads(output)
            attachment = resdict["attachment"]
            self.assertEqual(attachment, "fudd", "Attachment: %s" % attachment)

    def test_renameNetwork(self):
        self.create_network(test_network1_data)
        res = self.client.do_request(TENANT_ID, 'GET', "/networks." + FORMAT)
        resdict = json.loads(res.read())
        net_id = resdict["networks"][0]["id"]

        data = test_network1_data.copy()
        data['network']['network-name'] = 'test_renamed'
        content_type = "application/" + FORMAT
        body = Serializer().serialize(data, content_type)
        res = self.client.do_request(TENANT_ID, 'PUT',
          "/networks/%s.%s" % (net_id, FORMAT), body=body)
        resdict = json.loads(res.read())
        self.assertTrue(resdict["networks"]["network"]["id"] == net_id,
          "Network_rename: renamed network has a different uuid")
        self.assertTrue(
            resdict["networks"]["network"]["name"] == "test_renamed",
            "Network rename didn't take effect")

    def test_createNetworkOnMultipleTenants(self):
        # Create the same network on multiple tenants
        self.create_network(test_network1_data, "tenant1")
        self.create_network(test_network1_data, "tenant2")

    def delete_networks(self, tenant_id=TENANT_ID):
        # Remove all the networks created on the tenant (including ports and
        # attachments)
        res = self.client.do_request(tenant_id, 'GET',
          "/networks." + FORMAT)
        resdict = json.loads(res.read())
        for n in resdict["networks"]:
            net_id = n["id"]
            # Delete all the ports
            res = self.client.do_request(tenant_id, 'GET',
              "/networks/%s/ports.%s" % (net_id, FORMAT))
            output = res.read()
            self.assertEqual(res.status, 200, "Bad response: %s" % output)
            resdict = json.loads(output)
            ids = []
            for p in resdict["ports"]:
                res = self.client.do_request(tenant_id, 'DELETE',
                  "/networks/%s/ports/%s/attachment.%s" % (net_id, p["id"],
                    FORMAT))
                res = self.client.do_request(tenant_id, 'DELETE',
                  "/networks/%s/ports/%s.%s" % (net_id, p["id"], FORMAT))
            # Now, remove the network
            res = self.client.do_request(tenant_id, 'DELETE',
              "/networks/" + net_id + "." + FORMAT)
            self.assertEqual(res.status, 202)

    def tearDown(self):
        self.delete_networks()

# Standard boilerplate to call the main() function.
if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(QuantumTest)
    unittest.TextTestRunner(verbosity=2).run(suite)

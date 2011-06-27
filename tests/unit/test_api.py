import quantum.api.ports as ports
import quantum.api.networks as networks
import tests.unit.testlib as testlib
import unittest


class APIPortsTest(unittest.TestCase):
    def setUp(self):
        self.port = ports.Controller()
        self.network = networks.Controller()

#    Fault names copied here for reference
#
#    _fault_names = {
#            400: "malformedRequest",
#            401: "unauthorized",
#            420: "networkNotFound",
#            421: "networkInUse",
#            430: "portNotFound",
#            431: "requestedStateInvalid",
#            432: "portInUse",
#            440: "alreadyAttached",
#            470: "serviceUnavailable",
#            471: "pluginFault"}

    def test_deletePort(self):
        tenant = "tenant1"
        network = "test1"
        req = testlib.create_network_request(tenant, network)
        network_obj = self.network.create(req, tenant)
        network_id = network_obj["networks"]["network"]["id"]
        req = testlib.create_empty_request()
        rv = self.port.create(req, tenant, network_id)
        port_id = rv["ports"]["port"]["id"]
        self.assertTrue(port_id > 0)
        rv = self.port.delete("", tenant, network_id, port_id)
        self.assertEqual(rv.status_int, 202)

    def test_deletePortNegative(self):
        tenant = "tenant1"
        network = "test1"

        # Check for network not found
        rv = self.port.delete("", tenant, network, 2)
        self.assertEqual(rv.wrapped_exc.status_int, 420)

        # Create a network to put the port on
        req = testlib.create_network_request(tenant, network)
        network_obj = self.network.create(req, tenant)
        network_id = network_obj["networks"]["network"]["id"]

        # Test for portnotfound
        rv = self.port.delete("", tenant, network_id, 2)
        self.assertEqual(rv.wrapped_exc.status_int, 430)

        # Test for portinuse
        rv = self.port.create(req, tenant, network_id)
        port_id = rv["ports"]["port"]["id"]
        req = testlib.create_attachment_request(tenant, network_id,
          port_id, "fudd")
        rv = self.port.attach_resource(req, tenant, network_id, port_id)
        self.assertEqual(rv.status_int, 202)
        rv = self.port.delete("", tenant, network_id, port_id)
        self.assertEqual(rv.wrapped_exc.status_int, 432)

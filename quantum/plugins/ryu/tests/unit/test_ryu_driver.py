# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
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

import uuid

import quantum.db.api as db
from quantum.plugins.ryu.tests.unit import utils
from quantum.plugins.ryu.tests.unit.basetest import BaseRyuTest
from quantum.plugins.ryu.tests.unit.utils import patch_fake_ryu_client


class RyuDriverTest(BaseRyuTest):
    """Class conisting of OFPRyuDriver unit tests"""
    def setUp(self):
        super(RyuDriverTest, self).setUp()

        # fake up ryu.app.client and ryu.app.rest_nw_id
        # With those, plugin can be tested without ryu installed
        self.module_patcher = patch_fake_ryu_client()
        self.module_patcher.start()

    def tearDown(self):
        self.module_patcher.stop()
        super(RyuDriverTest, self).tearDown()

    def test_ryu_driver(self):
        from ryu.app import client as client_mod
        from ryu.app import rest_nw_id as rest_nw_id_mod

        self.mox.StubOutClassWithMocks(client_mod, 'OFPClient')
        client_mock = client_mod.OFPClient(utils.FAKE_REST_ADDR)

        self.mox.StubOutWithMock(client_mock, 'update_network')
        self.mox.StubOutWithMock(client_mock, 'create_network')
        self.mox.StubOutWithMock(client_mock, 'delete_network')
        client_mock.update_network(rest_nw_id_mod.NW_ID_EXTERNAL)
        uuid0 = '01234567-89ab-cdef-0123-456789abcdef'

        def fake_uuid4():
            return uuid0

        self.stubs.Set(uuid, 'uuid4', fake_uuid4)
        uuid1 = '12345678-9abc-def0-1234-56789abcdef0'
        net1 = utils.Net(uuid1)

        client_mock.update_network(uuid0)
        client_mock.create_network(uuid1)
        client_mock.delete_network(uuid1)
        self.mox.ReplayAll()

        db.network_create('test', uuid0)

        from quantum.plugins.ryu import ryu_quantum_plugin
        ryu_driver = ryu_quantum_plugin.OFPRyuDriver(self.config)
        ryu_driver.create_network(net1)
        ryu_driver.delete_network(net1)
        self.mox.VerifyAll()

        db.network_destroy(uuid0)

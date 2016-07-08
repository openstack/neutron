# Copyright (c) 2016 Red Hat
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

import mock

from oslo_utils import uuidutils
import testtools

from neutron.common import utils as common_utils
from neutron.services.trunk.drivers.openvswitch.agent import trunk_manager
from neutron.tests import base

NATIVE_OVSDB_CONNECTION = (
    'neutron.agent.ovsdb.impl_idl.OvsdbIdl.ovsdb_connection')


class TrunkParentPortTestCase(base.BaseTestCase):
    def setUp(self):
        super(TrunkParentPortTestCase, self).setUp()
        # Mock out connecting to ovsdb
        mock.patch(NATIVE_OVSDB_CONNECTION).start()
        trunk_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        trunk_mac = common_utils.get_random_mac('fa:16:3e:00:00:00'.split(':'))
        self.trunk = trunk_manager.TrunkParentPort(
            trunk_id, port_id, trunk_mac)

    def test_multiple_transactions(self):
        def method_inner(trunk):
            with trunk.ovsdb_transaction() as txn:
                return id(txn)

        def method_outer(trunk):
            with trunk.ovsdb_transaction() as txn:
                return method_inner(trunk), id(txn)

        with self.trunk.ovsdb_transaction() as txn1:
            mock_commit = mock.patch.object(txn1, 'commit').start()
            txn_inner_id, txn_outer_id = method_outer(self.trunk)
            self.assertFalse(mock_commit.called)
        self.assertTrue(mock_commit.called)
        self.assertTrue(id(txn1) == txn_inner_id == txn_outer_id)

    def test_transaction_raises_error(self):
        class MyException(Exception):
            pass

        with testtools.ExpectedException(MyException):
            with self.trunk.ovsdb_transaction() as txn1:
                mock.patch.object(txn1, 'commit').start()
                raise MyException()
        self.assertIsNone(self.trunk._transaction)
        with self.trunk.ovsdb_transaction() as txn2:
            mock.patch.object(txn2, 'commit').start()
            self.assertIsNot(txn1, txn2)

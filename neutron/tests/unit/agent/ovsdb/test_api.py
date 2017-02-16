# Copyright (c) 2017 Red Hat, Inc.
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
import testtools

from neutron.agent.ovsdb import api
from neutron.tests import base


class FakeTransaction(object):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, tb):
        self.commit()

    def commit(self):
        """Serves just for mock."""


class TestingAPI(api.API):
    def create_transaction(self, check_error=False, log_errors=True, **kwargs):
        return FakeTransaction()

    def add_manager(self, connection_uri):
        pass

    def get_manager(self):
        pass

    def remove_manager(self, connection_uri):
        pass

    def add_br(self, name, may_exist=True, datapath_type=None):
        pass

    def del_br(self, name, if_exists=True):
        pass

    def br_exists(self, name):
        pass

    def port_to_br(self, name):
        pass

    def iface_to_br(self, name):
        pass

    def list_br(self):
        pass

    def br_get_external_id(self, name, field):
        pass

    def db_create(self, table, **col_values):
        pass

    def db_destroy(self, table, record):
        pass

    def db_set(self, table, record, *col_values):
        pass

    def db_add(self, table, record, column, *values):
        pass

    def db_clear(self, table, record, column):
        pass

    def db_get(self, table, record, column):
        pass

    def db_list(self, table, records=None, columns=None, if_exists=False):
        pass

    def db_find(self, table, *conditions, **kwargs):
        pass

    def set_controller(self, bridge, controllers):
        pass

    def del_controller(self, bridge):
        pass

    def get_controller(self, bridge):
        pass

    def set_fail_mode(self, bridge, mode):
        pass

    def add_port(self, bridge, port, may_exist=True):
        pass

    def del_port(self, port, bridge=None, if_exists=True):
        pass

    def list_ports(self, bridge):
        pass

    def list_ifaces(self, bridge):
        pass


class TransactionTestCase(base.BaseTestCase):
    def setUp(self):
        super(TransactionTestCase, self).setUp()
        self.api = TestingAPI(None)
        mock.patch.object(FakeTransaction, 'commit').start()

    def test_transaction_nested(self):
        with self.api.transaction() as txn1:
            with self.api.transaction() as txn2:
                self.assertIs(txn1, txn2)
        txn1.commit.assert_called_once_with()

    def test_transaction_no_nested_transaction_after_error(self):
        class TestException(Exception):
            pass

        with testtools.ExpectedException(TestException):
            with self.api.transaction() as txn1:
                raise TestException()

        with self.api.transaction() as txn2:
            self.assertIsNot(txn1, txn2)

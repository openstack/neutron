# Copyright (c) 2016 Red Hat, Inc.
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

from ovsdbapp import exceptions
import testtools

from neutron.agent.ovsdb import impl_idl
from neutron.tests import base


class TransactionTestCase(base.BaseTestCase):
    def test_commit_raises_exception_on_timeout(self):
        transaction = impl_idl.NeutronOVSDBTransaction(mock.sentinel,
                                                       mock.Mock(), 1)
        with self.assert_max_execution_time(10):
            with testtools.ExpectedException(exceptions.TimeoutException):
                transaction.commit()

    def test_post_commit_does_not_raise_exception(self):
        with mock.patch.object(impl_idl.NeutronOVSDBTransaction,
                               "do_post_commit", side_effect=Exception):
            transaction = impl_idl.NeutronOVSDBTransaction(mock.sentinel,
                                                           mock.Mock(), 0)
            transaction.post_commit(mock.Mock())

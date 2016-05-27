# Copyright (c) 2016 Mirantis, Inc.
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
import sqlalchemy as sa

from neutron.db import model_base
from neutron.tests import base as test_base


class GetUniqueKeysTestCase(test_base.BaseTestCase):

    def test_with_unique_constraints(self):
        model = mock.Mock()
        metadata = sa.MetaData()
        model.__table__ = sa.Table(
            "test_table", metadata,
            sa.Column("a", sa.Integer, unique=True),
            sa.Column("b", sa.Integer),
            sa.Column("c", sa.Integer),
            sa.Column("d", sa.Integer),
            sa.UniqueConstraint("c", "d"))
        expected = {("a",), ("c", "d")}
        observed = {tuple(sorted(key)) for key in
                    model_base.get_unique_keys(model)}
        self.assertEqual(expected, observed)

    def test_without_unique_constraints(self):
        model = mock.Mock()
        metadata = sa.MetaData()
        model.__table__ = sa.Table(
            "test_table", metadata,
            sa.Column("a", sa.Integer),
            sa.Column("b", sa.Integer))
        self.assertEqual([], model_base.get_unique_keys(model))

    def test_not_a_model(self):
        self.assertEqual([], model_base.get_unique_keys(None))

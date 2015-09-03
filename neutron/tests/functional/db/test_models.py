# Copyright (c) 2014 OpenStack Foundation.
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

import sqlalchemy

from neutron.tests import base


class TestDBCreation(base.BaseTestCase):
    """Check database schema can be created without conflicts.

    For each test case is created a SQLite memory database.

    """

    def setUp(self):
        super(TestDBCreation, self).setUp()
        self.engine = sqlalchemy.create_engine('sqlite://')

    def _test_creation(self, module):
        metadata = module.get_metadata()
        metadata.create_all(self.engine)

    def test_head_creation(self):
        from neutron.db.migration.models import head
        self._test_creation(head)

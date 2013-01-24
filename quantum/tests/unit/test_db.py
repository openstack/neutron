# Copyright (c) 2013 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test of DB API"""

import unittest2 as unittest

import mock

import quantum.db.api as db
from quantum.openstack.common import cfg


class DBTestCase(unittest.TestCase):
    def test_db_reconnect(self):
        cfg.CONF.set_override('sql_max_retries', 3, 'DATABASE')
        with mock.patch.object(db, 'register_models') as mock_register:
            mock_register.return_value = False
            db.configure_db()

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

import contextlib

from oslo.config import cfg
from oslo.db.sqlalchemy import test_base

from neutron import context
from neutron.db import sqlalchemyutils
from neutron.tests import base


class TestSettingTXIsolationLevel(base.BaseTestCase,
                                  test_base.MySQLOpportunisticTestCase):
    """Check that transaction isolation level indeed changes."""

    def setUp(self):
        super(TestSettingTXIsolationLevel, self).setUp()
        cfg.CONF.set_override('connection',
                              self.engine.url,
                              group='database')

    def _get_session_tx_isolation(self, session):
        sql = "SELECT @@tx_isolation;"
        res = session.connection().execute(sql)
        res = [r for r in res]
        res = [r for r in res[0]]
        return res[0]

    def test_set_tx_iso_level_changes_back_and_forth_mysql(self):
        ctx = context.get_admin_context()
        default_level = sqlalchemyutils.get_default_tx_level(self.engine)
        other_level = ("READ COMMITTED" if default_level == "REPEATABLE READ"
                       else "REPEATABLE READ")
        with contextlib.nested(
            ctx.session.begin(subtransactions=True),
            sqlalchemyutils.set_mysql_tx_isolation_level(
                ctx.session, other_level)
        ):
            res = self._get_session_tx_isolation(ctx.session)
            self.assertEqual(other_level.replace(' ', '-'), res)
        #check that context manager changes tx isolation level back
        res = self._get_session_tx_isolation(ctx.session)
        self.assertEqual(default_level.replace(' ', '-'), res)

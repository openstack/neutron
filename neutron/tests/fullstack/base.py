# Copyright 2015 Red Hat, Inc.
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

from oslo_config import cfg
from oslo_db.sqlalchemy import test_base

from neutron.db.migration.models import head  # noqa
from neutron.db import model_base


class BaseFullStackTestCase(test_base.MySQLOpportunisticTestCase):
    """Base test class for full-stack tests."""

    def __init__(self, environment, *args, **kwargs):
        super(BaseFullStackTestCase, self).__init__(*args, **kwargs)
        self.environment = environment

    def setUp(self):
        super(BaseFullStackTestCase, self).setUp()
        self.create_db_tables()

        self.environment.test_name = self.get_name()
        self.useFixture(self.environment)

        self.client = self.environment.neutron_server.client

    def get_name(self):
        class_name, test_name = self.id().split(".")[-2:]
        return "%s.%s" % (class_name, test_name)

    def create_db_tables(self):
        """Populate the new database.

        MySQLOpportunisticTestCase creates a new database for each test, but
        these need to be populated with the appropriate tables. Before we can
        do that, we must change the 'connection' option which the Neutron code
        knows to look at.

        Currently, the username and password options are hard-coded by
        oslo.db and neutron/tests/functional/contrib/gate_hook.sh. Also,
        we only support MySQL for now, but the groundwork for adding Postgres
        is already laid.
        """
        conn = ("mysql+pymysql://%(username)s:%(password)s"
                "@127.0.0.1/%(db_name)s" % {
                    'username': test_base.DbFixture.USERNAME,
                    'password': test_base.DbFixture.PASSWORD,
                    'db_name': self.engine.url.database})

        self.original_conn = cfg.CONF.database.connection
        self.addCleanup(self._revert_connection_address)
        cfg.CONF.set_override('connection', conn, group='database')

        model_base.BASEV2.metadata.create_all(self.engine)

    def _revert_connection_address(self):
        cfg.CONF.set_override('connection',
                              self.original_conn,
                              group='database')

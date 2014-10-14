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
from neutron.tests.fullstack import fullstack_fixtures as f_fixtures


class BaseFullStackTestCase(test_base.MySQLOpportunisticTestCase):
    """Base test class for full-stack tests.

    :param process_fixtures: a list of fixture classes (not instances).
    """

    def setUp(self):
        super(BaseFullStackTestCase, self).setUp()
        self.create_db_tables()

        self.neutron_server = self.useFixture(
            f_fixtures.NeutronServerFixture())
        self.client = self.neutron_server.client

    @property
    def test_name(self):
        """Return the name of the test currently running."""
        return self.id().split(".")[-1]

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
        conn = "mysql://%(username)s:%(password)s@127.0.0.1/%(db_name)s" % {
            'username': test_base.DbFixture.USERNAME,
            'password': test_base.DbFixture.PASSWORD,
            'db_name': self.engine.url.database}
        cfg.CONF.set_override('connection', conn, group='database')
        model_base.BASEV2.metadata.create_all(self.engine)

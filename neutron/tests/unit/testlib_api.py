# Copyright 2012 OpenStack Foundation
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

import fixtures
import six
import testtools

from neutron.db import api as db_api
# Import all data models
from neutron.db.migration.models import head  # noqa
from neutron.db import model_base
from neutron.tests import base
from neutron import wsgi


class ExpectedException(testtools.ExpectedException):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if super(ExpectedException, self).__exit__(exc_type,
                                                   exc_value,
                                                   traceback):
            self.exception = exc_value
            return True
        return False


def create_request(path, body, content_type, method='GET',
                   query_string=None, context=None):
    if query_string:
        url = "%s?%s" % (path, query_string)
    else:
        url = path
    req = wsgi.Request.blank(url)
    req.method = method
    req.headers = {}
    req.headers['Accept'] = content_type
    if isinstance(body, six.text_type):
        req.body = body.encode()
    else:
        req.body = body
    if context:
        req.environ['neutron.context'] = context
    return req


class SqlFixture(fixtures.Fixture):

    # flag to indicate that the models have been loaded
    _TABLES_ESTABLISHED = False

    def _setUp(self):
        # Register all data models
        engine = db_api.get_engine()
        if not SqlFixture._TABLES_ESTABLISHED:
            model_base.BASEV2.metadata.create_all(engine)
            SqlFixture._TABLES_ESTABLISHED = True

        def clear_tables():
            with engine.begin() as conn:
                for table in reversed(
                        model_base.BASEV2.metadata.sorted_tables):
                    conn.execute(table.delete())

        self.addCleanup(clear_tables)


class SqlTestCaseLight(base.DietTestCase):
    """All SQL taste, zero plugin/rpc sugar"""

    def setUp(self):
        super(SqlTestCaseLight, self).setUp()
        self.useFixture(SqlFixture())


class SqlTestCase(base.BaseTestCase):

    def setUp(self):
        super(SqlTestCase, self).setUp()
        self.useFixture(SqlFixture())


class WebTestCase(SqlTestCase):
    fmt = 'json'

    def setUp(self):
        super(WebTestCase, self).setUp()
        json_deserializer = wsgi.JSONDeserializer()
        self._deserializers = {
            'application/json': json_deserializer,
        }

    def deserialize(self, response):
        ctype = 'application/%s' % self.fmt
        data = self._deserializers[ctype].deserialize(response.body)['body']
        return data

    def serialize(self, data):
        ctype = 'application/%s' % self.fmt
        result = wsgi.Serializer().serialize(data, ctype)
        return result


class SubDictMatch(object):

    def __init__(self, sub_dict):
        self.sub_dict = sub_dict

    def __eq__(self, super_dict):
        return all(item in super_dict.items()
                   for item in self.sub_dict.items())

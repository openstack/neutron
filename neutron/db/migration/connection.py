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

from oslo_db.sqlalchemy import session


class DBConnection:
    """Context manager class which handles a DB connection.

       An existing connection can be passed as a parameter. When
       nested block is complete the new connection will be closed.
       This class is not thread safe.
    """

    def __init__(self, connection_url, connection=None):
        self.connection = connection
        self.connection_url = connection_url
        self.new_engine = False

    def __enter__(self):
        self.new_engine = self.connection is None
        if self.new_engine:
            self.engine = session.create_engine(self.connection_url)
            self.connection = self.engine.connect()
        return self.connection

    def __exit__(self, type, value, traceback):
        if self.new_engine:
            try:
                self.connection.close()
            finally:
                self.engine.dispose()

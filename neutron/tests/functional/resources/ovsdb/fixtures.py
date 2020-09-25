# Copyright 2020 Red Hat, Inc.
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
from ovsdbapp.backend.ovs_idl import connection

from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovsdb_monitor


class OVNIdlConnectionFixture(fixtures.Fixture):
    def __init__(self, idl=None, constr=None, helper=None, timeout=60):
        self.idl = idl or ovsdb_monitor.BaseOvnIdl.from_server(
            constr, helper)
        self.connection = connection.Connection(
            idl=self.idl, timeout=timeout)

    def _setUp(self):
        self.addCleanup(self.stop)
        self.connection.start()

    def stop(self):
        self.connection.stop()

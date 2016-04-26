# Copyright 2016 Hewlett Packard Enterprise Development Company, LP
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

from neutron import context
from neutron.db import models_v2
from neutron.services.trunk import db
from neutron.services.trunk import exceptions
from neutron.tests.unit import testlib_api


class TrunkDBTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(TrunkDBTestCase, self).setUp()
        self.ctx = context.get_admin_context()

    def _add_network(self, net_id):
        with self.ctx.session.begin(subtransactions=True):
            self.ctx.session.add(models_v2.Network(id=net_id))

    def _add_port(self, net_id, port_id):
        with self.ctx.session.begin(subtransactions=True):
            port = models_v2.Port(id=port_id,
                                  network_id=net_id,
                                  mac_address='foo_mac_%s' % port_id,
                                  admin_state_up=True,
                                  status='DOWN',
                                  device_id='',
                                  device_owner='')
            self.ctx.session.add(port)

    def test_create_trunk_raise_port_in_use(self):
        self._add_network('foo_net')
        self._add_port('foo_net', 'foo_port')
        db.create_trunk(self.ctx, 'foo_port')
        self.assertRaises(exceptions.TrunkPortInUse,
                          db.create_trunk,
                          self.ctx, 'foo_port')

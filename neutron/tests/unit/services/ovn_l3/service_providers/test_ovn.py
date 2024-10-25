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
#

from unittest import mock

from neutron_lib.callbacks import events
from oslo_config import cfg

from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.db.models import l3
from neutron.db.models import l3_attrs
from neutron.services.ovn_l3.service_providers import ovn
from neutron.tests.unit import testlib_api

DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class TestOVN(testlib_api.SqlTestCase):

    def setUp(self):
        super().setUp()
        self.setup_coreplugin(DB_PLUGIN_KLASS)
        self.fake_l3 = mock.MagicMock()
        self.provider = ovn.OvnDriver(self.fake_l3)
        self.context = mock.MagicMock()
        self.router = l3.Router(id='fake-uuid',
                                flavor_id=None)
        self.router['extra_attributes'] = l3_attrs.RouterExtraAttributes()
        ovn_conf.register_opts()
        cfg.CONF.set_override('enable_distributed_floating_ip', True,
                              group='ovn')

    @mock.patch('neutron.db.ovn_revision_numbers_db.create_initial_revision')
    def test_process_router_create_precommit(self, cir):
        router_req = {'id': 'fake-uuid',
                      'flavor_id': None}
        payload = events.DBEventPayload(
            self.context,
            resource_id=self.router['id'],
            states=(router_req,),
            metadata={'router_db': self.router})
        self.provider._process_router_create_precommit('resource', 'event',
                                                       self, payload)
        cir.assert_called_once()

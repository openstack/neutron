# Copyright (c) 2017 OpenStack Foundation.
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

from neutron import manager
from neutron.tests import base


class NeutronPluginBaseV2TestCase(base.BaseTestCase):

    def test_can_load_core_plugin_without_datastore(self):
        cfg.CONF.set_override("core_plugin", 'neutron.tests.unit.dummy_plugin.'
                              'DummyCorePluginWithoutDatastore')
        manager.init()

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

from unittest import mock

from neutron.api.rpc.callbacks.consumer import registry as cons_registry
from neutron.api.rpc.callbacks.producer import registry as prod_registry
from neutron.api.rpc.callbacks import resource_manager
from neutron.tests.unit import testlib_api


class BaseQosTestCase(testlib_api.SqlTestCase):
    def setUp(self):
        super().setUp()

        with mock.patch.object(
                resource_manager.ResourceCallbacksManager, '_singleton',
                new_callable=mock.PropertyMock(return_value=False)):

            self.cons_mgr = resource_manager.ConsumerResourceCallbacksManager()
            self.prod_mgr = resource_manager.ProducerResourceCallbacksManager()
            for mgr in (self.cons_mgr, self.prod_mgr):
                mgr.clear()

        mock.patch.object(
            cons_registry, '_get_manager', return_value=self.cons_mgr).start()

        mock.patch.object(
            prod_registry, '_get_manager', return_value=self.prod_mgr).start()

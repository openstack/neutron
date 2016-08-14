# Copyright 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import mock

from neutron.callbacks import events
from neutron.services.trunk import constants as trunk_consts
from neutron.services.trunk.rpc import backend
from neutron.tests import base


class ServerSideRpcBackendTest(base.BaseTestCase):
    # TODO(fitoduarte): add more test to improve coverage of module
    @mock.patch("neutron.api.rpc.callbacks.resource_manager."
                "ResourceCallbacksManager.register")
    @mock.patch("neutron.callbacks.manager.CallbacksManager.subscribe")
    def test___init__(self, mocked_subscribe, mocked_register):
        test_obj = backend.ServerSideRpcBackend()

        calls = [mock.call(test_obj.process_event,
                           trunk_consts.TRUNK,
                           events.AFTER_CREATE),
                 mock.call(test_obj.process_event,
                           trunk_consts.TRUNK,
                           events.AFTER_DELETE),
                 mock.call(test_obj.process_event,
                           trunk_consts.SUBPORTS,
                           events.AFTER_CREATE),
                 mock.call(test_obj.process_event,
                           trunk_consts.SUBPORTS,
                           events.AFTER_DELETE)
                 ]
        mocked_subscribe.assert_has_calls(calls, any_order=True)

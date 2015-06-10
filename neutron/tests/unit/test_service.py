# Copyright 2015 Mirantis Inc.
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

import mock

from neutron import service
from neutron.tests import base


class TestRpcWorker(base.BaseTestCase):

    @mock.patch("neutron.policy.refresh")
    @mock.patch("neutron.common.config.setup_logging")
    def test_reset(self, setup_logging_mock, refresh_mock):
        _plugin = mock.Mock()

        rpc_worker = service.RpcWorker(_plugin)
        rpc_worker.reset()

        setup_logging_mock.assert_called_once_with()
        refresh_mock.assert_called_once_with()

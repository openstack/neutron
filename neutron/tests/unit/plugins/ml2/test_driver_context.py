# Copyright (c) 2013 OpenStack Foundation
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
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants

from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2 import models
from neutron.tests import base


class TestPortContext(base.BaseTestCase):

    # REVISIT(rkukura): These was originally for DvrPortContext tests,
    # but DvrPortContext functionality has been folded into the
    # regular PortContext class. Tests for non-DVR-specific
    # functionality are needed here as well.

    def test_host(self):
        plugin = mock.Mock()
        plugin_context = mock.Mock()
        network = mock.MagicMock()
        binding = models.PortBinding()

        port = {'device_owner': constants.DEVICE_OWNER_DVR_INTERFACE}
        binding.host = 'foohost'

        with mock.patch.object(driver_context.segments_db,
                               'get_network_segments'):
            ctx = driver_context.PortContext(plugin,
                                             plugin_context,
                                             port,
                                             network,
                                             binding,
                                             None)
        self.assertEqual('foohost', ctx.host)

    def test_host_super(self):
        plugin = mock.Mock()
        plugin_context = mock.Mock()
        network = mock.MagicMock()
        binding = models.PortBinding()

        port = {'device_owner': constants.DEVICE_OWNER_COMPUTE_PREFIX,
                portbindings.HOST_ID: 'host'}
        binding.host = 'foohost'

        with mock.patch.object(driver_context.segments_db,
                               'get_network_segments'):
            ctx = driver_context.PortContext(plugin,
                                             plugin_context,
                                             port,
                                             network,
                                             binding,
                                             None)
        self.assertEqual('host', ctx.host)

    def test_status(self):
        plugin = mock.Mock()
        plugin_context = mock.Mock()
        network = mock.MagicMock()
        binding = models.PortBinding()

        port = {'device_owner': constants.DEVICE_OWNER_DVR_INTERFACE}
        binding.status = 'foostatus'

        with mock.patch.object(driver_context.segments_db,
                               'get_network_segments'):
            ctx = driver_context.PortContext(plugin,
                                             plugin_context,
                                             port,
                                             network,
                                             binding,
                                             None)
        self.assertEqual('foostatus', ctx.status)

    def test_status_super(self):
        plugin = mock.Mock()
        plugin_context = mock.Mock()
        network = mock.MagicMock()
        binding = models.PortBinding()

        port = {'device_owner': constants.DEVICE_OWNER_COMPUTE_PREFIX,
                'status': 'status'}
        binding.status = 'foostatus'

        with mock.patch.object(driver_context.segments_db,
                               'get_network_segments'):
            ctx = driver_context.PortContext(plugin,
                                             plugin_context,
                                             port,
                                             network,
                                             binding,
                                             None)
        self.assertEqual('status', ctx.status)

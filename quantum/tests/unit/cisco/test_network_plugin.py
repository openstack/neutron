# Copyright (c) 2012 OpenStack, LLC.
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

import inspect
import logging
import mock

from quantum.api.v2.router import APIRouter
from quantum.common import config
from quantum.common.test_lib import test_config
from quantum import context
from quantum.db import api as db
from quantum.db import l3_db
from quantum.extensions import _quotav2_model as quotav2_model
from quantum.manager import QuantumManager
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.db import network_db_v2
from quantum.plugins.cisco.db import network_models_v2
from quantum.plugins.openvswitch import ovs_models_v2
from quantum.openstack.common import cfg
from quantum.tests.unit import test_db_plugin
from quantum.wsgi import JSONDeserializer

LOG = logging.getLogger(__name__)


class CiscoNetworkPluginV2TestCase(test_db_plugin.QuantumDbPluginV2TestCase):

    _plugin_name = 'quantum.plugins.cisco.network_plugin.PluginV2'

    def setUp(self):
        def new_init():
            db.configure_db({'sql_connection': 'sqlite:///:memory:',
                             'base': network_models_v2.model_base.BASEV2})

        with mock.patch.object(network_db_v2,
                               'initialize', new=new_init):
            super(CiscoNetworkPluginV2TestCase, self).setUp(self._plugin_name)

    def _get_plugin_ref(self):
        plugin_obj = QuantumManager.get_plugin()
        if getattr(plugin_obj, "_master"):
            plugin_ref = plugin_obj
        else:
            plugin_ref = getattr(plugin_obj, "_model").\
                _plugins[const.VSWITCH_PLUGIN]

        return plugin_ref


class TestCiscoBasicGet(CiscoNetworkPluginV2TestCase,
                        test_db_plugin.TestBasicGet):
    pass


class TestCiscoV2HTTPResponse(CiscoNetworkPluginV2TestCase,
                              test_db_plugin.TestV2HTTPResponse):

    pass


class TestCiscoPortsV2(CiscoNetworkPluginV2TestCase,
                       test_db_plugin.TestPortsV2):

    def test_create_ports_bulk_emulated_plugin_failure(self):
        real_has_attr = hasattr

        #ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            plugin_ref = self._get_plugin_ref()
            orig = plugin_ref.create_port
            with mock.patch.object(plugin_ref,
                                   'create_port') as patched_plugin:

                def side_effect(*args, **kwargs):
                    return self._do_side_effect(patched_plugin, orig,
                                                *args, **kwargs)

                patched_plugin.side_effect = side_effect
                with self.network() as net:
                    res = self._create_port_bulk('json', 2,
                                                 net['network']['id'],
                                                 'test',
                                                 True)
                    # We expect a 500 as we injected a fault in the plugin
                    self._validate_behavior_on_bulk_failure(res, 'ports')

    def test_create_ports_bulk_native_plugin_failure(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk port create")
        ctx = context.get_admin_context()
        with self.network() as net:
            plugin_ref = self._get_plugin_ref()
            orig = plugin_ref.create_port
            with mock.patch.object(plugin_ref,
                                   'create_port') as patched_plugin:

                def side_effect(*args, **kwargs):
                    return self._do_side_effect(patched_plugin, orig,
                                                *args, **kwargs)

                patched_plugin.side_effect = side_effect
                res = self._create_port_bulk('json', 2, net['network']['id'],
                                             'test', True, context=ctx)
                # We expect a 500 as we injected a fault in the plugin
                self._validate_behavior_on_bulk_failure(res, 'ports')


class TestCiscoNetworksV2(CiscoNetworkPluginV2TestCase,
                          test_db_plugin.TestNetworksV2):

    def test_create_networks_bulk_emulated_plugin_failure(self):
        real_has_attr = hasattr

        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        plugin_ref = self._get_plugin_ref()
        orig = plugin_ref.create_network
        #ensures the API choose the emulation code path
        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            with mock.patch.object(plugin_ref,
                                   'create_network') as patched_plugin:
                def side_effect(*args, **kwargs):
                    return self._do_side_effect(patched_plugin, orig,
                                                *args, **kwargs)
                patched_plugin.side_effect = side_effect
                res = self._create_network_bulk('json', 2, 'test', True)
                LOG.debug("response is %s" % res)
                # We expect a 500 as we injected a fault in the plugin
                self._validate_behavior_on_bulk_failure(res, 'networks')

    def test_create_networks_bulk_native_plugin_failure(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk network create")
        plugin_ref = self._get_plugin_ref()
        orig = plugin_ref.create_network
        with mock.patch.object(plugin_ref,
                               'create_network') as patched_plugin:

            def side_effect(*args, **kwargs):
                return self._do_side_effect(patched_plugin, orig,
                                            *args, **kwargs)

            patched_plugin.side_effect = side_effect
            res = self._create_network_bulk('json', 2, 'test', True)
            # We expect a 500 as we injected a fault in the plugin
            self._validate_behavior_on_bulk_failure(res, 'networks')


class TestCiscoSubnetsV2(CiscoNetworkPluginV2TestCase,
                         test_db_plugin.TestSubnetsV2):

    def test_create_subnets_bulk_emulated_plugin_failure(self):
        real_has_attr = hasattr

        #ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            plugin_ref = self._get_plugin_ref()
            orig = plugin_ref.create_subnet
            with mock.patch.object(plugin_ref,
                                   'create_subnet') as patched_plugin:

                def side_effect(*args, **kwargs):
                    self._do_side_effect(patched_plugin, orig,
                                         *args, **kwargs)

                patched_plugin.side_effect = side_effect
                with self.network() as net:
                    res = self._create_subnet_bulk('json', 2,
                                                   net['network']['id'],
                                                   'test')
                # We expect a 500 as we injected a fault in the plugin
                self._validate_behavior_on_bulk_failure(res, 'subnets')

    def test_create_subnets_bulk_native_plugin_failure(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk subnet create")
        plugin_ref = self._get_plugin_ref()
        orig = plugin_ref.create_subnet
        with mock.patch.object(plugin_ref,
                               'create_subnet') as patched_plugin:
            def side_effect(*args, **kwargs):
                return self._do_side_effect(patched_plugin, orig,
                                            *args, **kwargs)

            patched_plugin.side_effect = side_effect
            with self.network() as net:
                res = self._create_subnet_bulk('json', 2,
                                               net['network']['id'],
                                               'test')

                # We expect a 500 as we injected a fault in the plugin
                self._validate_behavior_on_bulk_failure(res, 'subnets')

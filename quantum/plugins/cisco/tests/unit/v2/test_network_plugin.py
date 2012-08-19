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
import os

from quantum.api.v2.router import APIRouter
from quantum.common import config
from quantum.common.test_lib import test_config
from quantum import context
from quantum.db import api as db
from quantum.extensions import _quotav2_model as quotav2_model
from quantum.manager import QuantumManager
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.db import network_db_v2
from quantum.plugins.cisco.db import network_models_v2
from quantum.openstack.common import cfg
from quantum.tests.unit import test_db_plugin
from quantum.wsgi import JSONDeserializer

LOG = logging.getLogger(__name__)


def curdir(*p):
    return os.path.join(os.path.dirname(__file__), *p)


class NetworkPluginV2TestCase(test_db_plugin.QuantumDbPluginV2TestCase):

    def setUp(self):
        db._ENGINE = None
        db._MAKER = None
        QuantumManager._instance = None
        self._tenant_id = 'test-tenant'

        json_deserializer = JSONDeserializer()
        self._deserializers = {
            'application/json': json_deserializer,
        }

        plugin = 'quantum.plugins.cisco.network_plugin.PluginV2'
        # Create the default configurations
        args = ['--config-file', curdir('quantumv2.conf.cisco.test')]
        # If test_config specifies some config-file, use it, as well
        for config_file in test_config.get('config_files', []):
            args.extend(['--config-file', config_file])
        config.parse(args=args)
        # Update the plugin
        cfg.CONF.set_override('core_plugin', plugin)
        cfg.CONF.set_override('base_mac', "12:34:56:78:90:ab")
        cfg.CONF.max_dns_nameservers = 2
        cfg.CONF.max_subnet_host_routes = 2

        def new_init():
            db.configure_db({'sql_connection': 'sqlite://',
                             'base': network_models_v2.model_base.BASEV2})

        with mock.patch.object(network_db_v2,
                               'initialize', new=new_init):
            self.api = APIRouter()

        def _is_native_bulk_supported():
            plugin_obj = QuantumManager.get_plugin()
            native_bulk_attr_name = ("_%s__native_bulk_support"
                                     % plugin_obj.__class__.__name__)
            return getattr(plugin_obj, native_bulk_attr_name, False)

        self._skip_native_bulk = not _is_native_bulk_supported()

        ext_mgr = test_config.get('extension_manager', None)
        if ext_mgr:
            self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        LOG.debug("%s.%s.%s done" % (__name__, self.__class__.__name__,
                                     inspect.stack()[0][3]))

    def tearDown(self):
        db.clear_db(network_models_v2.model_base.BASEV2)
        db._ENGINE = None
        db._MAKER = None

        cfg.CONF.reset()

    def _get_plugin_ref(self):
        plugin_obj = QuantumManager.get_plugin()
        if getattr(plugin_obj, "_master"):
            plugin_ref = plugin_obj
        else:
            plugin_ref = getattr(plugin_obj, "_model").\
                _plugins[const.VSWITCH_PLUGIN]

        return plugin_ref


class TestV2HTTPResponse(NetworkPluginV2TestCase,
                         test_db_plugin.TestV2HTTPResponse):

    pass


class TestPortsV2(NetworkPluginV2TestCase, test_db_plugin.TestPortsV2):

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


class TestNetworksV2(NetworkPluginV2TestCase, test_db_plugin.TestNetworksV2):

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


class TestSubnetsV2(NetworkPluginV2TestCase, test_db_plugin.TestSubnetsV2):

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

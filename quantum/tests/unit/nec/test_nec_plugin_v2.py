# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 NEC Corporation.  All rights reserved.
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
# @author: Ryota MIBU

from quantum.plugins.nec.common import config
from quantum.tests.unit import test_db_plugin


class NECPluginTestBase(object):

    def setUp(self):
        # Make sure at each test a new instance of the plugin is returned
        test_db_plugin.QuantumManager._instance = None

        self._tenant_id = 'test-tenant'

        json_deserializer = test_db_plugin.JSONDeserializer()
        self._deserializers = {
            'application/json': json_deserializer,
        }

        plugin = 'quantum.plugins.nec.nec_plugin.NECPluginV2'
        config.CONF.set_override('core_plugin', plugin)
        driver = "quantum.tests.unit.nec.stub_ofc_driver.StubOFCDriver"
        config.CONF.set_override('driver', driver, 'OFC')
        config.CONF.set_override('rpc_backend',
                                 'quantum.openstack.common.rpc.impl_fake')
        self.api = test_db_plugin.APIRouter()
        self._skip_native_bulk = False
        super(NECPluginTestBase, self).setUp(plugin)


# TODO(r-mibu): write UT for packet_filters.
class TestPacketFiltersV2(NECPluginTestBase,
                          test_db_plugin.QuantumDbPluginV2TestCase):
    pass

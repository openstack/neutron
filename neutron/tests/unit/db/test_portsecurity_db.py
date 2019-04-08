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
from neutron_lib.api.definitions import port_security
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory

from neutron.db import portsecurity_db as pd
from neutron.db import portsecurity_db_common as pdc
from neutron.tests import base

common = pdc.PortSecurityDbCommon


class FakePlugin(pd.PortSecurityDbMixin):

    supported_extension_aliases = [port_security.ALIAS]


class PortSecurityDbMixinTestCase(base.BaseTestCase):

    def setUp(self):
        super(PortSecurityDbMixinTestCase, self).setUp()
        self.plugin = FakePlugin()
        directory.add_plugin(constants.CORE, self.plugin)

    @mock.patch.object(common, '_extend_port_security_dict')
    def test__extend_port_security_dict_relies_on_common(self, extend):
        response = mock.Mock()
        dbdata = mock.Mock()
        self.plugin._extend_port_security_dict(response, dbdata)
        extend.assert_called_once_with(response, dbdata)

    @mock.patch.object(common, '_extend_port_security_dict')
    def test__extend_port_security_dict_ignored_if_extension_disabled(self,
                                                                      extend):
        response = mock.Mock()
        dbdata = mock.Mock()
        self.plugin.supported_extension_aliases = []
        self.plugin._extend_port_security_dict(response, dbdata)
        self.assertFalse(extend.called)

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
from sqlalchemy.orm import exc

from neutron.db import portsecurity_db_common as pdc
from neutron.extensions import portsecurity as psec
from neutron.tests import base


common = pdc.PortSecurityDbCommon


class PortSecurityDbCommonTestCase(base.BaseTestCase):

    def setUp(self):
        super(PortSecurityDbCommonTestCase, self).setUp()
        self.common = common()

    def _test__get_security_binding_no_binding(self, getter):
        port_sec_enabled = True
        req = {psec.PORTSECURITY: port_sec_enabled}
        res = {}
        with mock.patch.object(
                self.common, '_model_query',
                create=True,
                side_effect=exc.NoResultFound):
            val = getter(req, res)
        self.assertEqual(port_sec_enabled, val)

    def test__get_port_security_binding_no_binding(self):
        self._test__get_security_binding_no_binding(
            self.common._get_port_security_binding)

    def test__get_network_security_binding_no_binding(self):
        self._test__get_security_binding_no_binding(
            self.common._get_network_security_binding)

    def _test__process_security_update_no_binding(self, creator, updater):
        req = {psec.PORTSECURITY: False}
        res = {}
        context = mock.Mock()
        with mock.patch.object(
                self.common, '_model_query',
                create=True,
                side_effect=exc.NoResultFound):
            updater(context, req, res)
        creator.assert_called_with(context, req, res)

    @mock.patch.object(common, '_process_port_port_security_create')
    def test__process_port_port_security_update_no_binding(self, creator):
            self._test__process_security_update_no_binding(
                creator,
                self.common._process_port_port_security_update)

    @mock.patch.object(common, '_process_network_port_security_create')
    def test__process_network_port_security_update_no_binding(self, creator):
            self._test__process_security_update_no_binding(
                creator,
                self.common._process_network_port_security_update)

    def test__extend_port_security_dict_no_port_security(self):
        for db_data in ({'port_security': None, 'name': 'net1'}, {}):
            response_data = {}
            self.common._extend_port_security_dict(response_data, db_data)
            self.assertTrue(response_data[psec.PORTSECURITY])

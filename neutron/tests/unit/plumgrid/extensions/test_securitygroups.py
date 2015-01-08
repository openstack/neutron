# Copyright 2014 PLUMgrid, Inc. All Rights Reserved.
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
#

"""
PLUMgrid plugin security group extension unit tests
"""

import mock
from oslo_utils import importutils

from neutron.plugins.plumgrid.plumgrid_plugin import plumgrid_plugin
from neutron.tests.unit import test_extension_security_group as ext_sg


PLUM_DRIVER = ('neutron.plugins.plumgrid.drivers.fake_plumlib.Plumlib')
FAKE_DIRECTOR = '1.1.1.1'
FAKE_PORT = '1234'
FAKE_USERNAME = 'fake_admin'
FAKE_PASSWORD = 'fake_password'
FAKE_TIMEOUT = '0'


class SecurityGroupsTestCase(ext_sg.SecurityGroupDBTestCase):
    _plugin_name = ('neutron.plugins.plumgrid.plumgrid_plugin.'
                    'plumgrid_plugin.NeutronPluginPLUMgridV2')

    def setUp(self):
        def mocked_plumlib_init(self):
            director_plumgrid = FAKE_DIRECTOR
            director_port = FAKE_PORT
            director_username = FAKE_USERNAME
            director_password = FAKE_PASSWORD
            timeout = FAKE_TIMEOUT
            self._plumlib = importutils.import_object(PLUM_DRIVER)
            self._plumlib.director_conn(director_plumgrid,
                                        director_port, timeout,
                                        director_username,
                                        director_password)

        with mock.patch.object(plumgrid_plugin.NeutronPluginPLUMgridV2,
                               'plumgrid_init', new=mocked_plumlib_init):
            super(SecurityGroupsTestCase, self).setUp(self._plugin_name)

    def tearDown(self):
        super(SecurityGroupsTestCase, self).tearDown()


class TestSecurityGroups(ext_sg.TestSecurityGroups, SecurityGroupsTestCase):

    pass

# Copyright (c) 2013-2014 OpenStack Foundation
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
# @author: Kyle Mestery, Cisco Systems, Inc.

import mock
import requests

from neutron.plugins.common import constants
from neutron.plugins.ml2 import config as config
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mechanism_odl
from neutron.plugins.ml2 import plugin
from neutron.tests import base
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import testlib_api

PLUGIN_NAME = 'neutron.plugins.ml2.plugin.Ml2Plugin'


class OpenDaylightTestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['logger', 'opendaylight'],
                                     'ml2')
        # Set URL/user/pass so init doesn't throw a cfg required error.
        # They are not used in these tests since sendjson is overwritten.
        config.cfg.CONF.set_override('url', 'http://127.0.0.1:9999', 'ml2_odl')
        config.cfg.CONF.set_override('username', 'someuser', 'ml2_odl')
        config.cfg.CONF.set_override('password', 'somepass', 'ml2_odl')

        super(OpenDaylightTestCase, self).setUp(PLUGIN_NAME)
        self.port_create_status = 'DOWN'
        self.segment = {'api.NETWORK_TYPE': ""}
        self.mech = mechanism_odl.OpenDaylightMechanismDriver()
        mechanism_odl.OpenDaylightMechanismDriver.sendjson = (
            self.check_sendjson)

    def check_sendjson(self, method, urlpath, obj, ignorecodes=[]):
        self.assertFalse(urlpath.startswith("http://"))

    def test_check_segment(self):
        """Validate the check_segment call."""
        self.segment[api.NETWORK_TYPE] = constants.TYPE_LOCAL
        self.assertTrue(self.mech.check_segment(self.segment))
        self.segment[api.NETWORK_TYPE] = constants.TYPE_FLAT
        self.assertFalse(self.mech.check_segment(self.segment))
        self.segment[api.NETWORK_TYPE] = constants.TYPE_VLAN
        self.assertTrue(self.mech.check_segment(self.segment))
        self.segment[api.NETWORK_TYPE] = constants.TYPE_GRE
        self.assertTrue(self.mech.check_segment(self.segment))
        self.segment[api.NETWORK_TYPE] = constants.TYPE_VXLAN
        self.assertTrue(self.mech.check_segment(self.segment))
        # Validate a network type not currently supported
        self.segment[api.NETWORK_TYPE] = 'mpls'
        self.assertFalse(self.mech.check_segment(self.segment))


class OpenDayLightMechanismConfigTests(testlib_api.SqlTestCase):

    def _set_config(self, url='http://127.0.0.1:9999', username='someuser',
                    password='somepass'):
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['logger', 'opendaylight'],
                                     'ml2')
        config.cfg.CONF.set_override('url', url, 'ml2_odl')
        config.cfg.CONF.set_override('username', username, 'ml2_odl')
        config.cfg.CONF.set_override('password', password, 'ml2_odl')

    def _test_missing_config(self, **kwargs):
        self._set_config(**kwargs)
        self.assertRaises(config.cfg.RequiredOptError,
                          plugin.Ml2Plugin)

    def test_valid_config(self):
        self._set_config()
        plugin.Ml2Plugin()

    def test_missing_url_raises_exception(self):
        self._test_missing_config(url=None)

    def test_missing_username_raises_exception(self):
        self._test_missing_config(username=None)

    def test_missing_password_raises_exception(self):
        self._test_missing_config(password=None)


class OpenDaylightMechanismTestBasicGet(test_plugin.TestBasicGet,
                                        OpenDaylightTestCase):
    pass


class OpenDaylightMechanismTestNetworksV2(test_plugin.TestNetworksV2,
                                          OpenDaylightTestCase):
    pass


class OpenDaylightMechanismTestSubnetsV2(test_plugin.TestSubnetsV2,
                                         OpenDaylightTestCase):
    pass


class OpenDaylightMechanismTestPortsV2(test_plugin.TestPortsV2,
                                       OpenDaylightTestCase):
    pass


class AuthMatcher(object):
    def __eq__(self, obj):
        return (obj.username == config.cfg.CONF.ml2_odl.username and
                obj.password == config.cfg.CONF.ml2_odl.password)


class OpenDaylightMechanismDriverTestCase(base.BaseTestCase):

    def setUp(self):
        super(OpenDaylightMechanismDriverTestCase, self).setUp()
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['logger', 'opendaylight'], 'ml2')
        config.cfg.CONF.set_override('url', 'http://127.0.0.1:9999', 'ml2_odl')
        config.cfg.CONF.set_override('username', 'someuser', 'ml2_odl')
        config.cfg.CONF.set_override('password', 'somepass', 'ml2_odl')
        self.mech = mechanism_odl.OpenDaylightMechanismDriver()
        self.mech.initialize()

    @staticmethod
    def _get_mock_delete_resource_context():
        current = {'id': '00000000-1111-2222-3333-444444444444'}
        context = mock.Mock(current=current)
        return context

    _status_code_msgs = {
        204: '',
        401: '401 Client Error: Unauthorized',
        403: '403 Client Error: Forbidden',
        404: '404 Client Error: Not Found',
        409: '409 Client Error: Conflict',
        501: '501 Server Error: Not Implemented'
    }

    @classmethod
    def _get_mock_request_response(cls, status_code):
        response = mock.Mock(status_code=status_code)
        response.raise_for_status = mock.Mock() if status_code < 400 else (
            mock.Mock(side_effect=requests.exceptions.HTTPError(
                cls._status_code_msgs[status_code])))
        return response

    def _test_delete_resource_postcommit(self, object_type, status_code,
                                         exc_class=None):
        self.mech.out_of_sync = False
        method = getattr(self.mech, 'delete_%s_postcommit' % object_type)
        context = self._get_mock_delete_resource_context()
        request_response = self._get_mock_request_response(status_code)
        with mock.patch('requests.request',
                        return_value=request_response) as mock_method:
            if exc_class is not None:
                self.assertRaises(exc_class, method, context)
            else:
                method(context)
        url = '%s/%ss/%s' % (config.cfg.CONF.ml2_odl.url, object_type,
                             context.current['id'])
        mock_method.assert_called_once_with(
            'delete', url=url, headers={'Content-Type': 'application/json'},
            data=None, auth=AuthMatcher(),
            timeout=config.cfg.CONF.ml2_odl.timeout)

    def test_delete_network_postcommit(self):
        self._test_delete_resource_postcommit('network',
                                              requests.codes.no_content)
        for status_code in (requests.codes.unauthorized,
                            requests.codes.not_found,
                            requests.codes.conflict):
            self._test_delete_resource_postcommit(
                'network', status_code, requests.exceptions.HTTPError)

    def test_delete_subnet_postcommit(self):
        self._test_delete_resource_postcommit('subnet',
                                              requests.codes.no_content)
        for status_code in (requests.codes.unauthorized,
                            requests.codes.not_found,
                            requests.codes.conflict,
                            requests.codes.not_implemented):
            self._test_delete_resource_postcommit(
                'subnet', status_code, requests.exceptions.HTTPError)

    def test_delete_port_postcommit(self):
        self._test_delete_resource_postcommit('port',
                                              requests.codes.no_content)
        for status_code in (requests.codes.unauthorized,
                            requests.codes.forbidden,
                            requests.codes.not_found,
                            requests.codes.not_implemented):
            self._test_delete_resource_postcommit(
                'port', status_code, requests.exceptions.HTTPError)

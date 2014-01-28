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

from neutron.plugins.common import constants
from neutron.plugins.ml2 import config as config
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mechanism_odl
from neutron.tests.unit import test_db_plugin as test_plugin

PLUGIN_NAME = 'neutron.plugins.ml2.plugin.Ml2Plugin'


class OpenDaylightTestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['logger', 'opendaylight'],
                                     'ml2')
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
        self.assertFalse(self.mech.check_segment(self.segment))
        self.segment[api.NETWORK_TYPE] = constants.TYPE_GRE
        self.assertTrue(self.mech.check_segment(self.segment))
        self.segment[api.NETWORK_TYPE] = constants.TYPE_VXLAN
        self.assertTrue(self.mech.check_segment(self.segment))
        # Validate a network type not currently supported
        self.segment[api.NETWORK_TYPE] = 'mpls'
        self.assertFalse(self.mech.check_segment(self.segment))


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

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2013 OpenStack Foundation
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

import mock

from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.plugins.ml2 import config as ml2_config
from neutron.plugins.ml2.drivers.brocade import (mechanism_brocade
                                                 as brocademechanism)
from neutron.tests.unit import test_db_plugin

LOG = logging.getLogger(__name__)
MECHANISM_NAME = ('neutron.plugins.ml2.'
                  'drivers.brocade.mechanism_brocade.BrocadeMechanism')


class TestBrocadeMechDriverV2(test_db_plugin.NeutronDbPluginV2TestCase):
    """Test Brocade VCS/VDX mechanism driver.
    """

    _mechanism_name = MECHANISM_NAME

    def setUp(self):

        _mechanism_name = MECHANISM_NAME

        ml2_opts = {
            'mechanism_drivers': ['brocade'],
            'tenant_network_types': ['vlan']}

        for opt, val in ml2_opts.items():
            ml2_config.cfg.CONF.set_override(opt, val, 'ml2')

        def mocked_brocade_init(self):
            self._driver = mock.MagicMock()

        with mock.patch.object(brocademechanism.BrocadeMechanism,
                               'brocade_init', new=mocked_brocade_init):
            super(TestBrocadeMechDriverV2, self).setUp()
            self.mechanism_driver = importutils.import_object(_mechanism_name)


class TestBrocadeMechDriverNetworksV2(test_db_plugin.TestNetworksV2,
                                      TestBrocadeMechDriverV2):
    pass


class TestBrocadeMechDriverPortsV2(test_db_plugin.TestPortsV2,
                                   TestBrocadeMechDriverV2):
    pass


class TestBrocadeMechDriverSubnetsV2(test_db_plugin.TestSubnetsV2,
                                     TestBrocadeMechDriverV2):
    pass


class TestBrocadeMechDriverFeaturesEnabledTestCase(TestBrocadeMechDriverV2):

    def setUp(self):
        super(TestBrocadeMechDriverFeaturesEnabledTestCase, self).setUp()

    def test_version_features(self):

        vf = True
        # Test for NOS version 4.0.3
        self.mechanism_driver.set_features_enabled("4.0.3", vf)
        # Verify
        pp_domain_support, virtual_fabric_enabled = (
            self.mechanism_driver.get_features_enabled()
        )
        self.assertFalse(pp_domain_support)
        self.assertTrue(virtual_fabric_enabled)

        # Test for NOS version 4.1.0
        vf = True
        self.mechanism_driver.set_features_enabled("4.1.0", vf)
        # Verify
        pp_domain_support, virtual_fabric_enabled = (
            self.mechanism_driver.get_features_enabled()
        )
        self.assertTrue(pp_domain_support)
        self.assertTrue(virtual_fabric_enabled)

        # Test for NOS version 4.1.3
        vf = False
        self.mechanism_driver.set_features_enabled("4.1.3", vf)
        # Verify
        pp_domain_support, virtual_fabric_enabled = (
            self.mechanism_driver.get_features_enabled()
        )
        self.assertTrue(pp_domain_support)
        self.assertFalse(virtual_fabric_enabled)

        # Test for NOS version 5.0.0
        vf = True
        self.mechanism_driver.set_features_enabled("5.0.0", vf)
        # Verify
        pp_domain_support, virtual_fabric_enabled = (
            self.mechanism_driver.get_features_enabled()
        )
        self.assertTrue(pp_domain_support)
        self.assertTrue(virtual_fabric_enabled)

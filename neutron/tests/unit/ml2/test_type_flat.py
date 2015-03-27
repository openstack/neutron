# Copyright (c) 2014 Thales Services SAS
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

from neutron.common import exceptions as exc
import neutron.db.api as db
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import config
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import type_flat
from neutron.tests.unit import testlib_api


FLAT_NETWORKS = ['flat_net1', 'flat_net2']


class FlatTypeTest(testlib_api.SqlTestCase):

    def setUp(self):
        super(FlatTypeTest, self).setUp()
        config.cfg.CONF.set_override('flat_networks', FLAT_NETWORKS,
                              group='ml2_type_flat')
        self.driver = type_flat.FlatTypeDriver()
        self.session = db.get_session()
        self.driver.physnet_mtus = []

    def _get_allocation(self, session, segment):
        return session.query(type_flat.FlatAllocation).filter_by(
            physical_network=segment[api.PHYSICAL_NETWORK]).first()

    def test_is_partial_segment(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'flat_net1'}
        self.assertFalse(self.driver.is_partial_segment(segment))

    def test_validate_provider_segment(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'flat_net1'}
        self.driver.validate_provider_segment(segment)

    def test_validate_provider_phynet_name(self):
        self.assertRaises(exc.InvalidInput,
                          self.driver._parse_networks,
                          entries=[''])

    def test_validate_provider_phynet_name_multiple(self):
        self.assertRaises(exc.InvalidInput,
                          self.driver._parse_networks,
                          entries=['flat_net1', ''])

    def test_validate_provider_segment_without_physnet_restriction(self):
        self.driver._parse_networks('*')
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'other_flat_net'}
        self.driver.validate_provider_segment(segment)

    def test_validate_provider_segment_with_missing_physical_network(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT}
        self.assertRaises(exc.InvalidInput,
                          self.driver.validate_provider_segment,
                          segment)

    def test_validate_provider_segment_with_unsupported_physical_network(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'other_flat_net'}
        self.assertRaises(exc.InvalidInput,
                          self.driver.validate_provider_segment,
                          segment)

    def test_validate_provider_segment_with_unallowed_segmentation_id(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'flat_net1',
                   api.SEGMENTATION_ID: 1234}
        self.assertRaises(exc.InvalidInput,
                          self.driver.validate_provider_segment,
                          segment)

    def test_reserve_provider_segment(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'flat_net1'}
        observed = self.driver.reserve_provider_segment(self.session, segment)
        alloc = self._get_allocation(self.session, observed)
        self.assertEqual(segment[api.PHYSICAL_NETWORK], alloc.physical_network)

    def test_release_segment(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'flat_net1'}
        self.driver.reserve_provider_segment(self.session, segment)
        self.driver.release_segment(self.session, segment)
        alloc = self._get_allocation(self.session, segment)
        self.assertIsNone(alloc)

    def test_reserve_provider_segment_already_reserved(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'flat_net1'}
        self.driver.reserve_provider_segment(self.session, segment)
        self.assertRaises(exc.FlatNetworkInUse,
                          self.driver.reserve_provider_segment,
                          self.session, segment)

    def test_allocate_tenant_segment(self):
        observed = self.driver.allocate_tenant_segment(self.session)
        self.assertIsNone(observed)

    def test_get_mtu(self):
        config.cfg.CONF.set_override('segment_mtu', 1475, group='ml2')
        config.cfg.CONF.set_override('path_mtu', 1400, group='ml2')
        self.driver.physnet_mtus = {'physnet1': 1450, 'physnet2': 1400}
        self.assertEqual(1450, self.driver.get_mtu('physnet1'))

        config.cfg.CONF.set_override('segment_mtu', 1375, group='ml2')
        config.cfg.CONF.set_override('path_mtu', 1400, group='ml2')
        self.driver.physnet_mtus = {'physnet1': 1450, 'physnet2': 1400}
        self.assertEqual(1375, self.driver.get_mtu('physnet1'))

        config.cfg.CONF.set_override('segment_mtu', 0, group='ml2')
        config.cfg.CONF.set_override('path_mtu', 1425, group='ml2')
        self.driver.physnet_mtus = {'physnet1': 1450, 'physnet2': 1400}
        self.assertEqual(1400, self.driver.get_mtu('physnet2'))

        config.cfg.CONF.set_override('segment_mtu', 0, group='ml2')
        config.cfg.CONF.set_override('path_mtu', 0, group='ml2')
        self.driver.physnet_mtus = {}
        self.assertEqual(0, self.driver.get_mtu('physnet1'))

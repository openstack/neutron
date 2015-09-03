# Copyright (c) 2014 OpenStack Foundation, all rights reserved.
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
from oslo_config import cfg

from neutron import context
from neutron.db import dvr_mac_db
from neutron.extensions import dvr
from neutron.tests.unit import testlib_api


class DVRDbMixinImpl(dvr_mac_db.DVRDbMixin):

    def __init__(self, notifier):
        self.notifier = notifier


class DvrDbMixinTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(DvrDbMixinTestCase, self).setUp()
        self.ctx = context.get_admin_context()
        self.mixin = DVRDbMixinImpl(mock.Mock())

    def _create_dvr_mac_entry(self, host, mac_address):
        with self.ctx.session.begin(subtransactions=True):
            entry = dvr_mac_db.DistributedVirtualRouterMacAddress(
                host=host, mac_address=mac_address)
            self.ctx.session.add(entry)

    def test__get_dvr_mac_address_by_host(self):
        with self.ctx.session.begin(subtransactions=True):
            entry = dvr_mac_db.DistributedVirtualRouterMacAddress(
                host='foo_host', mac_address='foo_mac_address')
            self.ctx.session.add(entry)
        result = self.mixin._get_dvr_mac_address_by_host(self.ctx, 'foo_host')
        self.assertEqual(entry, result)

    def test__get_dvr_mac_address_by_host_not_found(self):
        self.assertRaises(dvr.DVRMacAddressNotFound,
                          self.mixin._get_dvr_mac_address_by_host,
                          self.ctx, 'foo_host')

    def test__create_dvr_mac_address_success(self):
        entry = {'host': 'foo_host', 'mac_address': '00:11:22:33:44:55:66'}
        with mock.patch.object(dvr_mac_db.utils, 'get_random_mac') as f:
            f.return_value = entry['mac_address']
            expected = self.mixin._create_dvr_mac_address(
                self.ctx, entry['host'])
        self.assertEqual(expected, entry)

    def test__create_dvr_mac_address_retries_exceeded_retry_logic(self):
        new_retries = 8
        cfg.CONF.set_override('mac_generation_retries', new_retries)
        self._create_dvr_mac_entry('foo_host_1', 'non_unique_mac')
        with mock.patch.object(dvr_mac_db.utils, 'get_random_mac') as f:
            f.return_value = 'non_unique_mac'
            self.assertRaises(dvr.MacAddressGenerationFailure,
                              self.mixin._create_dvr_mac_address,
                              self.ctx, "foo_host_2")
        self.assertEqual(new_retries, f.call_count)

    def test_delete_dvr_mac_address(self):
        self._create_dvr_mac_entry('foo_host', 'foo_mac_address')
        self.mixin.delete_dvr_mac_address(self.ctx, 'foo_host')
        count = self.ctx.session.query(
            dvr_mac_db.DistributedVirtualRouterMacAddress).count()
        self.assertFalse(count)

    def test_get_dvr_mac_address_list(self):
        self._create_dvr_mac_entry('host_1', 'mac_1')
        self._create_dvr_mac_entry('host_2', 'mac_2')
        mac_list = self.mixin.get_dvr_mac_address_list(self.ctx)
        self.assertEqual(2, len(mac_list))

    def test_get_dvr_mac_address_by_host_existing_host(self):
        self._create_dvr_mac_entry('foo_host', 'foo_mac')
        with mock.patch.object(self.mixin,
                               '_get_dvr_mac_address_by_host') as f:
            self.mixin.get_dvr_mac_address_by_host(self.ctx, 'foo_host')
            self.assertEqual(1, f.call_count)

    def test_get_dvr_mac_address_by_host_missing_host(self):
        with mock.patch.object(self.mixin, '_create_dvr_mac_address') as f:
            self.mixin.get_dvr_mac_address_by_host(self.ctx, 'foo_host')
            self.assertEqual(1, f.call_count)

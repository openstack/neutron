# Copyright 2026 Red Hat, Inc.
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

from unittest import mock

from oslo_utils import uuidutils

from neutron.db import dns_db
from neutron.db.dns_db import extensions as dns_extensions
from neutron.db.dns_db import fip_obj
from neutron.tests import base

FAKE_FIP_ID = uuidutils.generate_uuid()
FAKE_FIP_ADDRESS = '198.51.100.10'
FAKE_DNS_NAME = 'myvm'
FAKE_DNS_DOMAIN = 'example.com.'


class TestDNSDbMixin(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.mixin = dns_db.DNSDbMixin()
        self.mixin._core_plugin = mock.Mock()
        self.mixin._dns_driver = mock.Mock()
        self.mixin._delete_floatingip_from_external_dns_service = mock.Mock()
        self.context = mock.Mock()
        self.floatingip_data = {
            'id': FAKE_FIP_ID,
            'floating_ip_address': FAKE_FIP_ADDRESS,
        }
        self.mock_ext_supported = mock.patch.object(
            dns_extensions, 'is_extension_supported',
            return_value=True).start()
        self.mock_get_object = mock.patch.object(
            fip_obj.FloatingIPDNS, 'get_object').start()

    def _get_mock_dns_data_db(self):
        mock_dns_data_db = mock.Mock()
        mock_dns_data_db.__getitem__ = mock.Mock(side_effect={
            'published_dns_domain': FAKE_DNS_DOMAIN,
            'published_dns_name': FAKE_DNS_NAME,
        }.__getitem__)
        return mock_dns_data_db

    def test_process_dns_floatingip_delete(self):
        mock_dns_data_db = self._get_mock_dns_data_db()
        self.mock_get_object.return_value = mock_dns_data_db

        self.mixin._process_dns_floatingip_delete(
            self.context, self.floatingip_data)

        self.mock_get_object.assert_called_once_with(
            self.context, floatingip_id=FAKE_FIP_ID)
        self.mixin._delete_floatingip_from_external_dns_service.\
            assert_called_once_with(
                self.context, FAKE_DNS_DOMAIN, FAKE_DNS_NAME,
                [FAKE_FIP_ADDRESS])
        mock_dns_data_db.delete.assert_called_once()

    def test_process_dns_floatingip_delete_no_dns_data(self):
        self.mock_get_object.return_value = None

        self.mixin._process_dns_floatingip_delete(
            self.context, self.floatingip_data)

        self.mixin._delete_floatingip_from_external_dns_service.\
            assert_not_called()

    def test_process_dns_floatingip_delete_no_dns_extension(self):
        self.mock_ext_supported.return_value = False

        self.mixin._process_dns_floatingip_delete(
            self.context, self.floatingip_data)

        self.mock_get_object.assert_not_called()
        self.mixin._delete_floatingip_from_external_dns_service.\
            assert_not_called()

    def test_process_dns_floatingip_delete_ext_dns_service_error(self):
        """The FloatingIPDNS DB row is deleted even if Designate call fails."""
        mock_dns_data_db = self._get_mock_dns_data_db()
        self.mock_get_object.return_value = mock_dns_data_db

        self.mixin._process_dns_floatingip_delete(
            self.context, self.floatingip_data)

        mock_dns_data_db.delete.assert_called_once()

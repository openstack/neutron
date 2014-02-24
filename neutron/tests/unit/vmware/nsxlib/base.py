# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2014 VMware, Inc.
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
#

import mock

from neutron.plugins.nicira.common import config  # noqa
from neutron.plugins.nicira import nsx_cluster
from neutron.plugins.nicira import NvpApiClient
from neutron.plugins.nicira import nvplib
from neutron.tests import base
from neutron.tests.unit import test_api_v2
from neutron.tests.unit.vmware import fake_nvpapiclient
from neutron.tests.unit.vmware import NSXAPI_NAME
from neutron.tests.unit.vmware import STUBS_PATH

_uuid = test_api_v2._uuid


class NsxlibTestCase(base.BaseTestCase):

    def setUp(self):
        # mock nvp api client
        self.fc = fake_nvpapiclient.FakeClient(STUBS_PATH)
        self.mock_nsxapi = mock.patch(NSXAPI_NAME, autospec=True)
        instance = self.mock_nsxapi.start()
        instance.return_value.login.return_value = "the_cookie"
        fake_version = getattr(self, 'fake_version', "3.0")
        instance.return_value.get_nvp_version.return_value = (
            NvpApiClient.NVPVersion(fake_version))

        def _fake_request(*args, **kwargs):
            return self.fc.fake_request(*args, **kwargs)

        instance.return_value.request.side_effect = _fake_request
        self.fake_cluster = nsx_cluster.NSXCluster(
            name='fake-cluster', nsx_controllers=['1.1.1.1:999'],
            default_tz_uuid=_uuid(), nsx_user='foo', nsx_password='bar')
        self.fake_cluster.api_client = NvpApiClient.NVPApiHelper(
            ('1.1.1.1', '999', True),
            self.fake_cluster.nsx_user, self.fake_cluster.nsx_password,
            self.fake_cluster.req_timeout, self.fake_cluster.http_timeout,
            self.fake_cluster.retries, self.fake_cluster.redirects)

        super(NsxlibTestCase, self).setUp()
        self.addCleanup(self.fc.reset_all)
        self.addCleanup(self.mock_nsxapi.stop)

    def _build_tag_dict(self, tags):
        # This syntax is needed for python 2.6 compatibility
        return dict((t['scope'], t['tag']) for t in tags)


class NsxlibNegativeBaseTestCase(base.BaseTestCase):

    def setUp(self):
        # mock nsx api client
        self.fc = fake_nvpapiclient.FakeClient(STUBS_PATH)
        self.mock_nsxapi = mock.patch(NSXAPI_NAME, autospec=True)
        instance = self.mock_nsxapi.start()
        instance.return_value.login.return_value = "the_cookie"
        # Choose 3.0, but the version is irrelevant for the aim of
        # these tests as calls are throwing up errors anyway
        fake_version = getattr(self, 'fake_version', "3.0")
        instance.return_value.get_nvp_version.return_value = (
            NvpApiClient.NVPVersion(fake_version))

        def _faulty_request(*args, **kwargs):
            raise nvplib.NvpApiClient.NvpApiException

        instance.return_value.request.side_effect = _faulty_request
        self.fake_cluster = nsx_cluster.NSXCluster(
            name='fake-cluster', nsx_controllers=['1.1.1.1:999'],
            default_tz_uuid=_uuid(), nsx_user='foo', nsx_password='bar')
        self.fake_cluster.api_client = NvpApiClient.NVPApiHelper(
            ('1.1.1.1', '999', True),
            self.fake_cluster.nsx_user, self.fake_cluster.nsx_password,
            self.fake_cluster.req_timeout, self.fake_cluster.http_timeout,
            self.fake_cluster.retries, self.fake_cluster.redirects)

        super(NsxlibNegativeBaseTestCase, self).setUp()
        self.addCleanup(self.fc.reset_all)
        self.addCleanup(self.mock_nsxapi.stop)

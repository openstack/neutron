# Copyright (c) 2012 OpenStack Foundation.
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

from neutron.common import config
from neutron.tests import base


class ConfigurationTest(base.BaseTestCase):

    def test_load_paste_app_not_found(self):
        self.config(api_paste_config='no_such_file.conf')
        with mock.patch.object(cfg.CONF, 'find_file', return_value=None) as ff:
            e = self.assertRaises(cfg.ConfigFilesNotFoundError,
                                  config.load_paste_app, 'app')
            ff.assert_called_once_with('no_such_file.conf')
            self.assertEqual(['no_such_file.conf'], e.config_files)

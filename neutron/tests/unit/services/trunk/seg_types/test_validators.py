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

from neutron_lib.services.trunk import constants

from neutron.services.trunk.seg_types import validators
from neutron.tests import base


class ValidatorsTestCase(base.BaseTestCase):

    def test_add_validator_raises_keyerror_on_redefinition(self):
        self.assertRaises(KeyError,
                          validators.add_validator,
                          constants.SEGMENTATION_TYPE_VLAN, mock.ANY)

    def test_add_validator_add_new_type(self):
        validators.add_validator('foo', lambda: None)
        self.assertIn('foo', validators._supported)

    def test_get_validator(self):
        self.assertIsNotNone(validators.get_validator(
            constants.SEGMENTATION_TYPE_VLAN))

    def test_get_validator_raises_keyerror_on_missing_validator(self):
        self.assertRaises(KeyError,
                          validators.get_validator, 'my_random_seg_type')

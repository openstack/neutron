# Copyright 2025 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron.agent.ovn.extensions import extension_manager
from neutron.tests import base


class OVNExtensionEventNoExtensionName(extension_manager.OVNExtensionEvent):
    pass


class TestOVNExtensionEvent(base.BaseTestCase):
    def test_class_with_no_extension_name(self):
        try:
            OVNExtensionEventNoExtensionName()
        except Exception as exc:
            msg = ('The class OVNExtensionEventNoExtensionName has no '
                   'extension name defined.')
            self.assertEqual(msg, str(exc))

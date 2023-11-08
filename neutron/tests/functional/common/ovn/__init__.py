# Copyright 2023 Red Hat, Inc.
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

import functools

from neutron.common.ovn import utils


def skip_if_additional_chassis_not_supported(sb_idl_attribute_name):
    def outer(f):
        @functools.wraps(f)
        def inner(self, *args, **kwargs):
            sb_idl = getattr(self, sb_idl_attribute_name)
            if not utils.is_additional_chassis_supported(sb_idl):
                raise self.skipException(
                    "Used OVN version schema does not have additional_chassis "
                    " column")
            return f(self, *args, **kwargs)
        return inner
    return outer

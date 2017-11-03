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

import copy

from neutron.common import exceptions


def convert_filters(**kwargs):
    result = copy.deepcopy(kwargs)
    if 'tenant_id' in result:
        if 'project_id' in result:
            raise exceptions.TenantIdProjectIdFilterConflict()

        result['project_id'] = result.pop('tenant_id')
    return result


class StringMatchingFilterObj(object):
    @property
    def is_contains(self):
        return bool(getattr(self, "contains", False))

    @property
    def is_starts(self):
        return bool(getattr(self, "starts", False))

    @property
    def is_ends(self):
        return bool(getattr(self, "ends", False))


class StringContains(StringMatchingFilterObj):

    def __init__(self, matching_string):
        super(StringContains, self).__init__()
        self.contains = matching_string


class StringStarts(StringMatchingFilterObj):

    def __init__(self, matching_string):
        super(StringStarts, self).__init__()
        self.starts = matching_string


class StringEnds(StringMatchingFilterObj):

    def __init__(self, matching_string):
        super(StringEnds, self).__init__()
        self.ends = matching_string

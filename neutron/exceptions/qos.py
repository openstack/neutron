# Copyright (c) 2021 Ericsson Software Technology
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

from neutron_lib import exceptions as e

from neutron._i18n import _


# TODO(przszc): Move to n-lib
class QosPlacementAllocationUpdateConflict(e.Conflict):
    message = _("Updating placement allocation with %(alloc_diff)s for "
                "consumer %(consumer)s failed. The requested resources would "
                "exceed the capacity available.")

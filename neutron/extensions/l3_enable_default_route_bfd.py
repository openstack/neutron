# Copyright 2023 Canonical Ltd.
# All rights reserved.
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

from neutron_lib.api.definitions import l3_enable_default_route_bfd as apidef
from neutron_lib.api import extensions


class L3_enable_default_route_bfd(extensions.APIExtensionDescriptor):

    api_definition = apidef

    def __init__(self):
        # NOTE(fnordahl): Temporary fix awaiting permanent fix in neutron-lib,
        # drop when change I9096685fb79a84e11a8547a5aaa16f7f2df48a56 is merged.
        apidef.RESOURCE_ATTRIBUTE_MAP[
            apidef.COLLECTION_NAME][apidef.ENABLE_DEFAULT_ROUTE_BFD].update(
                {'default': None})
        super().__init__()

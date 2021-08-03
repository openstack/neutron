# Copyright 2021 Huawei, Inc.
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

from neutron_lib.api.definitions import local_ip as local_ip_apidef

from neutron.db import local_ip_db


class LocalIPPlugin(local_ip_db.LocalIPDbMixin):
    """Implementation of the Neutron logging api plugin."""

    supported_extension_aliases = [local_ip_apidef.ALIAS]

    __native_pagination_support = True
    __native_sorting_support = True
    __filter_validation_support = True

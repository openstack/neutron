# Copyright (c) 2017 NEC Corporation.  All rights reserved.
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

from neutron_lib.api.definitions import data_plane_status
from neutron_lib.api import extensions


class Data_plane_status(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return data_plane_status.NAME

    @classmethod
    def get_alias(cls):
        return data_plane_status.ALIAS

    @classmethod
    def get_description(cls):
        return data_plane_status.DESCRIPTION

    @classmethod
    def get_updated(cls):
        return data_plane_status.UPDATED_TIMESTAMP

    def get_required_extensions(self):
        return data_plane_status.REQUIRED_EXTENSIONS or []

    def get_optional_extensions(self):
        return data_plane_status.OPTIONAL_EXTENSIONS or []

    def get_extended_resources(self, version):
        if version == "2.0":
            return data_plane_status.RESOURCE_ATTRIBUTE_MAP
        else:
            return {}

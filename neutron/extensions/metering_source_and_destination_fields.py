# Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron_lib.api.definitions import metering_source_and_destination_filters
from neutron_lib.api import extensions


class Metering_source_and_destination_fields(
        extensions.APIExtensionDescriptor):

    api_definition = metering_source_and_destination_filters

    @classmethod
    def get_extended_resources(cls, version):
        sub_resource_map = super(Metering_source_and_destination_fields, cls
                                 ).get_extended_resources(version)

        processed_sub_resource_map = {}
        for value in sub_resource_map.values():
            parent_def = value['parent']
            collection_name = parent_def['collection_name']
            member_name = parent_def['member_name']

            if collection_name == member_name:
                processed_sub_resource_map[
                    collection_name] = value['parameters']
            else:
                processed_sub_resource_map[
                    collection_name] = {member_name: value['parameters']}

        return processed_sub_resource_map

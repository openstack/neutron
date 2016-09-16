# Copyright 2016 HuaWei Technologies.
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

from neutron.api import extensions


class Timestamp_ext(extensions.ExtensionDescriptor):
    """Extension class supporting timestamp.

    This class is used by neutron's extension framework for adding timestamp
    to neutron extension resources.
    """

    @classmethod
    def get_name(cls):
        return "Standardattr Extension Timestamps"

    @classmethod
    def get_alias(cls):
        return "timestamp_ext"

    @classmethod
    def get_description(cls):
        return ("This extension adds create/update timestamps for all "
                "standard neutron resources not included by the "
                "'timestamp_core' extension.")

    @classmethod
    def get_updated(cls):
        return "2016-05-05T10:00:00-00:00"

    def get_extended_resources(self, version):
        # NOTE(kevinbenton): this extension is basically a no-op because
        # the timestamp_core extension already defines all of the resources
        # now.
        return {}

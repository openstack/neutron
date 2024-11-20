# Copyright (c) 2024 Red Hat, Inc.
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

from neutron_lib.api.definitions import quota_check_limit
from neutron_lib.api import extensions


# NOTE(ralonsoh): once [1] is merged, use
# ``neutron_lib.api.definitions.quota_check_limit_default`` instead.
# [1] https://review.opendev.org/c/openstack/neutron-lib/+/926777
ALIAS = 'quota-check-limit-default'
IS_SHIM_EXTENSION = True
IS_STANDARD_ATTR_EXTENSION = False
NAME = 'Quota engine limit check by default'
DESCRIPTION = ('By default, the Neutron quota engine checks the resource '
               'usage before applying a new quota limit')
UPDATED_TIMESTAMP = '2024-08-21T16:00:00-00:00'
RESOURCE_ATTRIBUTE_MAP = {}
SUB_RESOURCE_ATTRIBUTE_MAP = {}
ACTION_MAP = {}
REQUIRED_EXTENSIONS = [quota_check_limit.ALIAS]
OPTIONAL_EXTENSIONS = []
ACTION_STATUS = {}


class Quota_check_limit_default(extensions.APIExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return NAME

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return DESCRIPTION

    @classmethod
    def get_updated(cls):
        return UPDATED_TIMESTAMP

    def get_required_extensions(self):
        return REQUIRED_EXTENSIONS

    def get_optional_extensions(self):
        return []

    @classmethod
    def get_extended_resources(cls, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        return {}

# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
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

from neutron_lib.api import extensions
from neutron_lib import constants


class Subnetallocation(extensions.ExtensionDescriptor):
    """Extension class supporting subnet allocation."""

    @classmethod
    def get_name(cls):
        return "Subnet Allocation"

    @classmethod
    def get_alias(cls):
        return constants.SUBNET_ALLOCATION_EXT_ALIAS

    @classmethod
    def get_description(cls):
        return "Enables allocation of subnets from a subnet pool"

    @classmethod
    def get_updated(cls):
        return "2015-03-30T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        return []

    def get_extended_resources(self, version):
        return {}

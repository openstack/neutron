# Copyright 2013 VMware, Inc.  All rights reserved.
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

from neutron.api.v2 import attributes
from neutron.common import exceptions as nexception


class PortSecurityPortHasSecurityGroup(nexception.InUse):
    message = _("Port has security group associated. Cannot disable port "
                "security or ip address until security group is removed")


class PortSecurityAndIPRequiredForSecurityGroups(nexception.InvalidInput):
    message = _("Port security must be enabled and port must have an IP"
                " address in order to use security groups.")


class PortSecurityBindingNotFound(nexception.InvalidExtensionEnv):
    message = _("Port does not have port security binding.")

PORTSECURITY = 'port_security_enabled'
EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        PORTSECURITY: {'allow_post': True, 'allow_put': True,
                       'convert_to': attributes.convert_to_boolean,
                       'enforce_policy': True,
                       'default': True,
                       'is_visible': True},
    },
    'ports': {
        PORTSECURITY: {'allow_post': True, 'allow_put': True,
                       'convert_to': attributes.convert_to_boolean,
                       'default': attributes.ATTR_NOT_SPECIFIED,
                       'enforce_policy': True,
                       'is_visible': True},
    }
}


class Portsecurity(object):
    """Extension class supporting port security."""

    @classmethod
    def get_name(cls):
        return "Port Security"

    @classmethod
    def get_alias(cls):
        return "port-security"

    @classmethod
    def get_description(cls):
        return "Provides port security"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/portsecurity/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2012-07-23T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

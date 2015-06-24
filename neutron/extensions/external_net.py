# Copyright (c) 2013 OpenStack Foundation.
# All Rights Reserved.
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
from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as nexception


class ExternalNetworkInUse(nexception.InUse):
    message = _("External network %(net_id)s cannot be updated to be made "
                "non-external, since it has existing gateway ports")


# For backward compatibility the 'router' prefix is kept.
EXTERNAL = 'router:external'
EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {EXTERNAL: {'allow_post': True,
                            'allow_put': True,
                            'default': False,
                            'is_visible': True,
                            'convert_to': attr.convert_to_boolean,
                            'enforce_policy': True,
                            'required_by_policy': True}}}


class External_net(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Neutron external network"

    @classmethod
    def get_alias(cls):
        return "external-net"

    @classmethod
    def get_description(cls):
        return _("Adds external network attribute to network resource.")

    @classmethod
    def get_updated(cls):
        return "2013-01-14T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

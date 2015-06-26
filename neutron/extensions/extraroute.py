# Copyright 2013, Nachi Ueno, NTT MCL, Inc.
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


# Extra Routes Exceptions
class InvalidRoutes(nexception.InvalidInput):
    message = _("Invalid format for routes: %(routes)s, %(reason)s")


class RouterInterfaceInUseByRoute(nexception.InUse):
    message = _("Router interface for subnet %(subnet_id)s on router "
                "%(router_id)s cannot be deleted, as it is required "
                "by one or more routes.")


class RoutesExhausted(nexception.BadRequest):
    message = _("Unable to complete operation for %(router_id)s. "
                "The number of routes exceeds the maximum %(quota)s.")

# Attribute Map
EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        'routes': {'allow_post': False, 'allow_put': True,
                   'validate': {'type:hostroutes': None},
                   'convert_to': attr.convert_none_to_empty_list,
                   'is_visible': True, 'default': attr.ATTR_NOT_SPECIFIED},
    }
}


class Extraroute(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Neutron Extra Route"

    @classmethod
    def get_alias(cls):
        return "extraroute"

    @classmethod
    def get_description(cls):
        return "Extra routes configuration for L3 router"

    @classmethod
    def get_updated(cls):
        return "2013-02-01T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            attr.PLURALS.update({'routes': 'route'})
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

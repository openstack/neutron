# Copyright (c) 2014 OpenStack Foundation.  All rights reserved.
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

import abc

import six

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions

DISTRIBUTED = 'distributed'
EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        DISTRIBUTED: {'allow_post': True,
                      'allow_put': True,
                      'is_visible': True,
                      'default': attributes.ATTR_NOT_SPECIFIED,
                      'convert_to': attributes.convert_to_boolean_if_not_none,
                      'enforce_policy': True},
    }
}


class DVRMacAddressNotFound(exceptions.NotFound):
    message = _("Distributed Virtual Router Mac Address for "
                "host %(host)s does not exist.")


class MacAddressGenerationFailure(exceptions.ServiceUnavailable):
    message = _("Unable to generate unique DVR mac for host %(host)s.")


class Dvr(extensions.ExtensionDescriptor):
    """Extension class supporting distributed virtual router."""

    @classmethod
    def get_name(cls):
        return "Distributed Virtual Router"

    @classmethod
    def get_alias(cls):
        return constants.L3_DISTRIBUTED_EXT_ALIAS

    @classmethod
    def get_description(cls):
        return "Enables configuration of Distributed Virtual Routers."

    @classmethod
    def get_updated(cls):
        return "2014-06-1T10:00:00-00:00"

    def get_required_extensions(self):
        return ["router"]

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        return []

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class DVRMacAddressPluginBase(object):

    @abc.abstractmethod
    def delete_dvr_mac_address(self, context, host):
        pass

    @abc.abstractmethod
    def get_dvr_mac_address_list(self, context):
        pass

    @abc.abstractmethod
    def get_dvr_mac_address_by_host(self, context, host):
        pass

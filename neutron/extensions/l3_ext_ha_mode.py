# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
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

from neutron_lib.api import converters
from neutron_lib import constants
from neutron_lib import exceptions

from neutron._i18n import _
from neutron.api import extensions
from neutron.common import constants as n_const

HA_INFO = 'ha'
EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        HA_INFO: {'allow_post': True, 'allow_put': True,
                  'default': constants.ATTR_NOT_SPECIFIED, 'is_visible': True,
                  'enforce_policy': True,
                  'convert_to': converters.convert_to_boolean_if_not_none}
    }
}


class HAmodeUpdateOfDvrNotSupported(NotImplementedError):
    message = _("Currently update of HA mode for a distributed router is "
                "not supported.")


class DVRmodeUpdateOfHaNotSupported(NotImplementedError):
    message = _("Currently update of distributed mode for an HA router is "
                "not supported.")


class HAmodeUpdateOfDvrHaNotSupported(NotImplementedError):
    message = _("Currently update of HA mode for a DVR/HA router is "
                "not supported.")


class DVRmodeUpdateOfDvrHaNotSupported(NotImplementedError):
    message = _("Currently update of distributed mode for a DVR/HA router "
                "is not supported")


class UpdateToDvrHamodeNotSupported(NotImplementedError):
    message = _("Currently updating a router to DVR/HA is not supported.")


class UpdateToNonDvrHamodeNotSupported(NotImplementedError):
    message = _("Currently updating a router from DVR/HA to non-DVR "
                " non-HA is not supported.")


class MaxVRIDAllocationTriesReached(exceptions.NeutronException):
    message = _("Failed to allocate a VRID in the network %(network_id)s "
                "for the router %(router_id)s after %(max_tries)s tries.")


class NoVRIDAvailable(exceptions.Conflict):
    message = _("No more Virtual Router Identifier (VRID) available when "
                "creating router %(router_id)s. The limit of number "
                "of HA Routers per tenant is 254.")


class HANetworkCIDRNotValid(exceptions.NeutronException):
    message = _("The HA Network CIDR specified in the configuration file "
                "isn't valid; %(cidr)s.")


class HANotEnoughAvailableAgents(exceptions.NeutronException):
    message = _("Not enough l3 agents available to ensure HA. Minimum "
                "required %(min_agents)s, available %(num_agents)s.")


class HAMaximumAgentsNumberNotValid(exceptions.NeutronException):
    message = _("max_l3_agents_per_router %(max_agents)s config parameter "
                "is not valid. It has to be greater than or equal to "
                "min_l3_agents_per_router %(min_agents)s.")


class HAMinimumAgentsNumberNotValid(exceptions.NeutronException):
    message = (_("min_l3_agents_per_router config parameter is not valid. "
                 "It has to be greater than or equal to %s for HA.") %
               n_const.MINIMUM_MINIMUM_AGENTS_FOR_HA)


class L3_ext_ha_mode(extensions.ExtensionDescriptor):
    """Extension class supporting virtual router in HA mode."""

    @classmethod
    def get_name(cls):
        return "HA Router extension"

    @classmethod
    def get_alias(cls):
        return constants.L3_HA_MODE_EXT_ALIAS

    @classmethod
    def get_description(cls):
        return "Add HA capability to routers."

    @classmethod
    def get_updated(cls):
        return "2014-04-26T00:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

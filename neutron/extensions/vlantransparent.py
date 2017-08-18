# Copyright (c) 2015 Cisco Systems, Inc.  All rights reserved.
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

from neutron_lib.api import converters
from neutron_lib.api import extensions
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib import exceptions
from oslo_config import cfg
from oslo_log import log as logging

from neutron._i18n import _

LOG = logging.getLogger(__name__)


class VlanTransparencyDriverError(exceptions.NeutronException):
    """Vlan Transparency not supported by all mechanism drivers."""
    message = _("Backend does not support VLAN Transparency.")


VLANTRANSPARENT = 'vlan_transparent'
EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        VLANTRANSPARENT: {'allow_post': True, 'allow_put': False,
                          'convert_to': converters.convert_to_boolean,
                          'default': constants.ATTR_NOT_SPECIFIED,
                          'is_visible': True},
    },
}


def disable_extension_by_config(aliases):
    if not cfg.CONF.vlan_transparent:
        if 'vlan-transparent' in aliases:
            aliases.remove('vlan-transparent')
        LOG.info('Disabled vlantransparent extension.')


def get_vlan_transparent(network):
    return (network['vlan_transparent']
            if ('vlan_transparent' in network and
                validators.is_attr_set(network['vlan_transparent']))
            else False)


class Vlantransparent(extensions.ExtensionDescriptor):
    """Extension class supporting vlan transparent networks."""

    @classmethod
    def get_name(cls):
        return "Vlantransparent"

    @classmethod
    def get_alias(cls):
        return "vlan-transparent"

    @classmethod
    def get_description(cls):
        return "Provides Vlan Transparent Networks"

    @classmethod
    def get_updated(cls):
        return "2015-03-23T09:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

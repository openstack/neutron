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

from oslo_config import cfg
from oslo_log import log as logging

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.common import exceptions as nexception
from neutron.i18n import _LI

LOG = logging.getLogger(__name__)


class VlanTransparencyDriverError(nexception.NeutronException):
    """Vlan Transparency not supported by all mechanism drivers."""
    message = _("Backend does not support VLAN Transparency.")


VLANTRANSPARENT = 'vlan_transparent'
EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        VLANTRANSPARENT: {'allow_post': True, 'allow_put': False,
                          'convert_to': attributes.convert_to_boolean,
                          'default': attributes.ATTR_NOT_SPECIFIED,
                          'is_visible': True},
    },
}


def disable_extension_by_config(aliases):
    if not cfg.CONF.vlan_transparent:
        if 'vlan-transparent' in aliases:
            aliases.remove('vlan-transparent')
        LOG.info(_LI('Disabled vlantransparent extension.'))


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

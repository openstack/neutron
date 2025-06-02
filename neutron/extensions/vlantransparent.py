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

from neutron_lib.api.definitions import vlantransparent as apidef
from neutron_lib.api import extensions
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def _disable_extension_by_config(aliases):
    if cfg.CONF.vlan_transparent is False:
        if 'vlan-transparent' in aliases:
            aliases.remove('vlan-transparent')
        LOG.info('Disabled vlantransparent extension.')


class Vlantransparent(extensions.APIExtensionDescriptor):
    """Extension class supporting vlan transparent networks."""

    api_definition = apidef

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

from neutron_lib.api.definitions import qinq as apidef
from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import validators
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def _disable_extension_by_config(aliases):
    if cfg.CONF.vlan_qinq is False:
        if apidef.ALIAS in aliases:
            aliases.remove(apidef.ALIAS)
        LOG.info('Disabled VLAN QinQ extension.')


def get_qinq(network):
    """Get the value of vlan_qinq from a network if set.

    :param network: The network dict to retrieve the value of vlan_qinq
        from.
    :returns: The value of vlan_qinq from the network dict if set in
        the dict, otherwise False is returned.
    """
    return (network[apidef.QINQ_FIELD]
            if (apidef.QINQ_FIELD in network and
                validators.is_attr_set(network[apidef.QINQ_FIELD]))
            else False)


class Qinq(api_extensions.APIExtensionDescriptor):
    """Extension class supporting vlan QinQ networks."""

    api_definition = apidef

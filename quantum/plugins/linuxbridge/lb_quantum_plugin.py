# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging

from quantum.api.v2 import attributes
from quantum.db import db_base_plugin_v2
from quantum.db import models_v2
from quantum.plugins.linuxbridge.db import l2network_db as cdb
from quantum import policy

LOG = logging.getLogger(__name__)


class LinuxBridgePluginV2(db_base_plugin_v2.QuantumDbPluginV2):
    """Implement the Quantum abstractions using Linux bridging.

    A new VLAN is created for each network.  An agent is relied upon
    to perform the actual Linux bridge configuration on each host.

    The provider extension is also supported. As discussed in
    https://bugs.launchpad.net/quantum/+bug/1023156, this class could
    be simplified, and filtering on extended attributes could be
    handled, by adding support for extended attributes to the
    QuantumDbPluginV2 base class. When that occurs, this class should
    be updated to take advantage of it.
    """

    supported_extension_aliases = ["provider"]

    def __init__(self):
        cdb.initialize(base=models_v2.model_base.BASEV2)
        LOG.debug("Linux Bridge Plugin initialization complete")

    # TODO(rkukura) Use core mechanism for attribute authorization
    # when available.

    def _check_provider_view_auth(self, context, network):
        return policy.check(context,
                            "extension:provider_network:view",
                            network)

    def _enforce_provider_set_auth(self, context, network):
        return policy.enforce(context,
                              "extension:provider_network:set",
                              network)

    def _extend_network_dict(self, context, network):
        if self._check_provider_view_auth(context, network):
            vlan_binding = cdb.get_vlan_binding(network['id'])
            network['provider:vlan_id'] = vlan_binding['vlan_id']

    def create_network(self, context, network):
        net = super(LinuxBridgePluginV2, self).create_network(context,
                                                              network)
        try:
            vlan_id = network['network'].get('provider:vlan_id')
            if vlan_id not in (None, attributes.ATTR_NOT_SPECIFIED):
                self._enforce_provider_set_auth(context, net)
                cdb.reserve_specific_vlanid(int(vlan_id), net['id'])
            else:
                vlan_id = cdb.reserve_vlanid()
            cdb.add_vlan_binding(vlan_id, net['id'])
            self._extend_network_dict(context, net)
        except:
            super(LinuxBridgePluginV2, self).delete_network(context,
                                                            net['id'])
            raise

        return net

    def update_network(self, context, id, network):
        net = super(LinuxBridgePluginV2, self).update_network(context, id,
                                                              network)
        self._extend_network_dict(context, net)
        return net

    def delete_network(self, context, id):
        vlan_binding = cdb.get_vlan_binding(id)
        cdb.release_vlanid(vlan_binding['vlan_id'])
        cdb.remove_vlan_binding(id)
        return super(LinuxBridgePluginV2, self).delete_network(context, id)

    def get_network(self, context, id, fields=None, verbose=None):
        net = super(LinuxBridgePluginV2, self).get_network(context, id,
                                                           None, verbose)
        self._extend_network_dict(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None, verbose=None):
        nets = super(LinuxBridgePluginV2, self).get_networks(context, filters,
                                                             None, verbose)
        for net in nets:
            self._extend_network_dict(context, net)
        # TODO(rkukura): Filter on extended attributes.
        return [self._fields(net, fields) for net in nets]

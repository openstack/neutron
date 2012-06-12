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
import uuid

from quantum import quantum_plugin_base_v2


LOG = logging.getLogger(__name__)


class QuantumEchoPlugin(quantum_plugin_base_v2.QuantumPluginBaseV2):

    """
    QuantumEchoPlugin is a demo plugin that doesn't
    do anything but demonstrate the concept of a
    concrete Quantum Plugin. Any call to this plugin
    will result in just a log statement with the name
    method that was called and its arguments.
    """

    def _log(self, name, context, **kwargs):
        kwarg_msg = ' '.join([('%s: |%s|' % (str(key), kwargs[key]))
                              for key in kwargs])

        # TODO(anyone) Add a nice __repr__ and __str__ to context
        #LOG.debug('%s context: %s %s' % (name, context, kwarg_msg))
        LOG.debug('%s %s' % (name, kwarg_msg))

    def create_subnet(self, context, subnet):
        self._log("create_subnet", context, subnet=subnet)
        res = {"id": str(uuid.uuid4())}
        res.update(subnet)
        return res

    def update_subnet(self, context, id, subnet):
        self._log("update_subnet", context, id=id, subnet=subnet)
        res = {"id": id}
        res.update(subnet)
        return res

    def get_subnet(self, context, id, show=None, verbose=None):
        self._log("get_subnet", context, id=id, show=show,
                  verbose=verbose)
        return {"id": id}

    def delete_subnet(self, context, id):
        self._log("delete_subnet", context, id=id)

    def get_subnets(self, context, filters=None, show=None, verbose=None):
        self._log("get_subnets", context, filters=filters, show=show,
                  verbose=verbose)
        return []

    def create_network(self, context, network):
        self._log("create_network", context, network=network)
        res = {"id": str(uuid.uuid4())}
        res.update(network)
        return res

    def update_network(self, context, id, network):
        self._log("update_network", context, id=id, network=network)
        res = {"id": id}
        res.update(network)
        return res

    def get_network(self, context, id, show=None, verbose=None):
        self._log("get_network", context, id=id, show=show,
                  verbose=verbose)
        return {"id": id}

    def delete_network(self, context, id):
        self._log("delete_network", context, id=id)

    def get_networks(self, context, filters=None, show=None, verbose=None):
        self._log("get_networks", context, filters=filters, show=show,
                  verbose=verbose)
        return []

    def create_port(self, context, port):
        self._log("create_port", context, port=port)
        res = {"id": str(uuid.uuid4())}
        res.update(port)
        return res

    def update_port(self, context, id, port):
        self._log("update_port", context, id=id, port=port)
        res = {"id": id}
        res.update(port)
        return res

    def get_port(self, context, id, show=None, verbose=None):
        self._log("get_port", context, id=id, show=show,
                  verbose=verbose)
        return {"id": id}

    def delete_port(self, context, id):
        self._log("delete_port", context, id=id)

    def get_ports(self, context, filters=None, show=None, verbose=None):
        self._log("get_ports", context, filters=filters, show=show,
                  verbose=verbose)
        return []

    supported_extension_aliases = ["FOXNSOX"]

    def method_to_support_foxnsox_extension(self, context):
        self._log("method_to_support_foxnsox_extension", context)

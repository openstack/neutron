"""
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Nicira Networks, Inc.  All rights reserved.
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
#
# @author: Brad Hall, Nicira Networks, Inc
#
"""

import logging

from quantum import wsgi
from quantum.extensions import _portstats_view as portstats_view
from quantum.api import faults
from quantum.common import exceptions as qexception
from quantum.common import extensions
from quantum.manager import QuantumManager


LOG = logging.getLogger("quantum.api.portstats")


class Portstats(object):
    def __init__(self):
        pass

    @classmethod
    def get_name(cls):
        return "Port Statistics"

    @classmethod
    def get_alias(cls):
        return "portstats"

    @classmethod
    def get_description(cls):
        return "Port Statistics"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/portstats/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2011-12-20T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """ Returns all defined resources """
        controller = StatsController(QuantumManager.get_plugin())
        parent_resource = dict(member_name="port",
                               collection_name="extensions/ovs/tenants/" + \
                               ":(tenant_id)/networks/:(network_id)/ports")
        return [extensions.ResourceExtension('stats', controller,
                                             parent=parent_resource)]


class StatsController(wsgi.Controller):
    _serialization_metadata = {
        "application/xml": {
            "attributes": {
                "stats": ["rx_bytes", "rx_packets", "rx_errors",
                          "tx_bytes", "tx_packets", "tx_errors"],
                },
            },
        }

    def __init__(self, plugin):
        self._resource_name = 'stats'
        self._plugin = plugin

    def _show(self, request, tenant_id, network_id, port_id):
        """Returns port statistics for a given port"""
        if not hasattr(self._plugin, "get_port_stats"):
            return \
                faults.QuantumHTTPError(
                    qexception.NotImplementedError("get_port_stats"))

        stats = self._plugin.get_port_stats(tenant_id, network_id,
                                            port_id)
        builder = portstats_view.get_view_builder(request)
        result = builder.build(stats, True)
        return dict(stats=result)

    def index(self, request, tenant_id, network_id, port_id):
        return self._show(request, tenant_id, network_id, port_id)

    def show(self, request, tenant_id, network_id, port_id, id):
        return self._show(request, tenant_id, network_id, port_id)

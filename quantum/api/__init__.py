# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Citrix Systems
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
# @author: Salvatore Orlando, Citrix Systems

"""
Quantum API controllers.
"""

import logging
import routes
import webob.dec
import webob.exc

from quantum import manager
from quantum.api import attachments
from quantum.api import networks
from quantum.api import ports
from quantum.common import flags
from quantum import wsgi


LOG = logging.getLogger('quantum.api')
FLAGS = flags.FLAGS


class APIRouter(wsgi.Router):
    """
    Base class for Quantum API routes.
    """
    _version = None

    def __init__(self, options=None):
        mapper = self._mapper()
        self._setup_routes(mapper, options)
        super(APIRouter, self).__init__(mapper)

    def _mapper(self):
        return routes.Mapper()

    def _setup_routes(self, mapper, options):
        self._setup_base_routes(mapper, options, self._version)

    def _setup_base_routes(self, mapper, options, version):
        """Routes common to all versions."""
        # Loads the quantum plugin
        # Note(salvatore-orlando): Should the plugin be versioned
        # I don't think so
        plugin = manager.QuantumManager.get_plugin(options)

        uri_prefix = '/tenants/{tenant_id}/'
        attachment_path = (
            '%snetworks/{network_id}/ports/{id}/attachment{.format}' %
            uri_prefix)
        mapper.resource('network', 'networks',
                        controller=networks.create_resource(plugin, version),
                        collection={'detail': 'GET'},
                        member={'detail': 'GET'},
                        path_prefix=uri_prefix)
        mapper.resource('port', 'ports',
                        controller=ports.create_resource(plugin, version),
                        collection={'detail': 'GET'},
                        member={'detail': 'GET'},
                        parent_resource=dict(
                            member_name='network',
                            collection_name='%snetworks' % uri_prefix))
        attachments_ctrl = attachments.create_resource(plugin, version)
        mapper.connect("get_resource",
                       attachment_path,
                       controller=attachments_ctrl,
                       action="get_resource",
                       conditions=dict(method=['GET']))
        mapper.connect("attach_resource",
                       attachment_path,
                       controller=attachments_ctrl,
                       action="attach_resource",
                       conditions=dict(method=['PUT']))
        mapper.connect("detach_resource",
                       attachment_path,
                       controller=attachments_ctrl,
                       action="detach_resource",
                       conditions=dict(method=['DELETE']))


class APIRouterV10(APIRouter):
    """
    API routes mappings for Quantum API v1.0
    """
    _version = '1.0'


class APIRouterV11(APIRouter):
    """
    API routes mappings for Quantum API v1.1
    """
    _version = '1.1'

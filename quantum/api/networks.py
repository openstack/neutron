# Copyright 2011 Citrix Systems.
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

import base64
import logging
import traceback

from webob import exc
from xml.dom import minidom

from quantum import manager
from quantum import quantum_plugin_base
from quantum.common import exceptions as exception
from quantum.common import flags
from quantum.common import wsgi
from quantum import utils
from quantum.api import api_common as common
from quantum.api import faults
import quantum.api

LOG = logging.getLogger('quantum.api.networks')
FLAGS = flags.FLAGS


class Controller(wsgi.Controller):
    """ Network API controller for Quantum API """

    #TODO (salvatore-orlando): adjust metadata for quantum
    _serialization_metadata = {
        "application/xml": {
            "attributes": {
                "server": ["id", "imageId", "name", "flavorId", "hostId",
                           "status", "progress", "adminPass", "flavorRef",
                           "imageRef"],
                "link": ["rel", "type", "href"],
            },
            "dict_collections": {
                "metadata": {"item_name": "meta", "item_key": "key"},
            },
            "list_collections": {
                "public": {"item_name": "ip", "item_key": "addr"},
                "private": {"item_name": "ip", "item_key": "addr"},
            },
        },
    }

    def __init__(self):
        self._setup_network_manager()
        super(Controller, self).__init__()

    def _setup_network_manager(self):
        self.network_manager=manager.QuantumManager().get_manager()
    
    def index(self, req, tenant_id):
        """ Returns a list of network names and ids """
        #TODO: this should be for a given tenant!!!
        LOG.debug("HERE - Controller.index")
        return self._items(req, tenant_id, is_detail=False)

    def _items(self, req, tenant_id, is_detail):
        """ Returns a list of networks. """
        test = self.network_manager.get_all_networks(tenant_id)
        #builder = self._get_view_builder(req)
        #servers = [builder.build(inst, is_detail)['server']
        #        for inst in limited_list]
        #return dict(servers=servers)
        return test
    
    def show(self, req, tenant_id, id):
        """ Returns network details by network id """
        try:
            return "SHOW NETWORK %s FOR TENANT %s" %(id,tenant_id)
        except exception.NotFound:
            return faults.Fault(exc.HTTPNotFound())

    def delete(self, req, id):
        """ Destroys the network with the given id """
        try:
            return "TEST NETWORK DELETE"
        except exception.NotFound:
            return faults.Fault(exc.HTTPNotFound())
        return exc.HTTPAccepted()

    def create(self, req):
        """ Creates a new network for a given tenant """
        #env = self._deserialize_create(req)
        #if not env:
        #    return faults.Fault(exc.HTTPUnprocessableEntity())
        return "TEST NETWORK CREATE"

    def _deserialize_create(self, request):
        """
        Deserialize a create request
        Overrides normal behavior in the case of xml content
        """
        #if request.content_type == "application/xml":
        #    deserializer = ServerCreateRequestXMLDeserializer()
        #    return deserializer.deserialize(request.body)
        #else:
        #    return self._deserialize(request.body, request.get_content_type())
        pass

    def update(self, req, id):
        """ Updates the name for the network wit the given id """
        if len(req.body) == 0:
            raise exc.HTTPUnprocessableEntity()

        inst_dict = self._deserialize(req.body, req.get_content_type())
        if not inst_dict:
            return faults.Fault(exc.HTTPUnprocessableEntity())

        try:
            return "TEST NETWORK UPDATE"
        except exception.NotFound:
            return faults.Fault(exc.HTTPNotFound())
        return exc.HTTPNoContent()


class NetworkCreateRequestXMLDeserializer(object):
    """
    Deserializer to handle xml-formatted server create requests.

    Handles standard server attributes as well as optional metadata
    and personality attributes
    """

    def deserialize(self, string):
        """Deserialize an xml-formatted server create request"""
        dom = minidom.parseString(string)
        server = self._extract_server(dom)
        return {'server': server}

    def _extract_server(self, node):
        """Marshal the server attribute of a parsed request"""
        server = {}
        server_node = self._find_first_child_named(node, 'server')
        for attr in ["name", "imageId", "flavorId"]:
            server[attr] = server_node.getAttribute(attr)
        metadata = self._extract_metadata(server_node)
        if metadata is not None:
            server["metadata"] = metadata
        personality = self._extract_personality(server_node)
        if personality is not None:
            server["personality"] = personality
        return server

    def _extract_metadata(self, server_node):
        """Marshal the metadata attribute of a parsed request"""
        metadata_node = self._find_first_child_named(server_node, "metadata")
        if metadata_node is None:
            return None
        metadata = {}
        for meta_node in self._find_children_named(metadata_node, "meta"):
            key = meta_node.getAttribute("key")
            metadata[key] = self._extract_text(meta_node)
        return metadata

    def _extract_personality(self, server_node):
        """Marshal the personality attribute of a parsed request"""
        personality_node = \
                self._find_first_child_named(server_node, "personality")
        if personality_node is None:
            return None
        personality = []
        for file_node in self._find_children_named(personality_node, "file"):
            item = {}
            if file_node.hasAttribute("path"):
                item["path"] = file_node.getAttribute("path")
            item["contents"] = self._extract_text(file_node)
            personality.append(item)
        return personality

    def _find_first_child_named(self, parent, name):
        """Search a nodes children for the first child with a given name"""
        for node in parent.childNodes:
            if node.nodeName == name:
                return node
        return None

    def _find_children_named(self, parent, name):
        """Return all of a nodes children who have the given name"""
        for node in parent.childNodes:
            if node.nodeName == name:
                yield node

    def _extract_text(self, node):
        """Get the text field contained by the given node"""
        if len(node.childNodes) == 1:
            child = node.childNodes[0]
            if child.nodeType == child.TEXT_NODE:
                return child.nodeValue
        return ""

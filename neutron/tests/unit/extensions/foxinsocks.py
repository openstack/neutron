# Copyright 2011 OpenStack Foundation.
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

import abc

from oslo_serialization import jsonutils

from neutron.api import extensions
from neutron import wsgi


class FoxInSocksController(wsgi.Controller):

    def index(self, request):
        return "Try to say this Mr. Knox, sir..."


class FoxInSocksPluginInterface(extensions.PluginInterface):

    @abc.abstractmethod
    def method_to_support_foxnsox_extension(self):
        pass


class Foxinsocks(object):

    def __init__(self):
        pass

    def get_plugin_interface(self):
        return FoxInSocksPluginInterface

    def get_name(self):
        return "Fox In Socks"

    def get_alias(self):
        return "FOXNSOX"

    def get_description(self):
        return "The Fox In Socks Extension"

    def get_updated(self):
        return "2011-01-22T13:25:27-06:00"

    def get_resources(self):
        resources = []
        resource = extensions.ResourceExtension('foxnsocks',
                                                FoxInSocksController())
        resources.append(resource)
        return resources

    def get_actions(self):
        return [extensions.ActionExtension('dummy_resources',
                                           'FOXNSOX:add_tweedle',
                                           self._add_tweedle_handler),
                extensions.ActionExtension('dummy_resources',
                                           'FOXNSOX:delete_tweedle',
                                           self._delete_tweedle_handler)]

    def get_request_extensions(self):
        request_exts = []

        def _goose_handler(req, res):
            #NOTE: This only handles JSON responses.
            # You can use content type header to test for XML.
            data = jsonutils.loads(res.body)
            data['FOXNSOX:googoose'] = req.GET.get('chewing')
            res.body = jsonutils.dumps(data)
            return res

        req_ext1 = extensions.RequestExtension('GET', '/dummy_resources/:(id)',
                                               _goose_handler)
        request_exts.append(req_ext1)

        def _bands_handler(req, res):
            #NOTE: This only handles JSON responses.
            # You can use content type header to test for XML.
            data = jsonutils.loads(res.body)
            data['FOXNSOX:big_bands'] = 'Pig Bands!'
            res.body = jsonutils.dumps(data)
            return res

        req_ext2 = extensions.RequestExtension('GET', '/dummy_resources/:(id)',
                                               _bands_handler)
        request_exts.append(req_ext2)
        return request_exts

    def _add_tweedle_handler(self, input_dict, req, id):
        return "Tweedle {0} Added.".format(
            input_dict['FOXNSOX:add_tweedle']['name'])

    def _delete_tweedle_handler(self, input_dict, req, id):
        return "Tweedle {0} Deleted.".format(
            input_dict['FOXNSOX:delete_tweedle']['name'])

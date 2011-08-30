# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Citrix System.
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

import logging

from webob import exc

from quantum.common import wsgi

XML_NS_V01 = 'http://netstack.org/quantum/api/v0.1'
XML_NS_V10 = 'http://netstack.org/quantum/api/v1.0'
LOG = logging.getLogger('quantum.api.api_common')


class QuantumController(wsgi.Controller):
    """ Base controller class for Quantum API """

    def __init__(self, plugin):
        self._plugin = plugin
        super(QuantumController, self).__init__()

    def _parse_request_params(self, req, params):
        results = {}
        data = {}
        # Parameters are expected to be in request body only
        if req.body:
            des_body = self._deserialize(req.body,
                                         req.best_match_content_type())
            data = des_body and des_body.get(self._resource_name, None)
            if not data:
                msg = ("Failed to parse request. Resource: " +
                       self._resource_name + " not found in request body")
                for line in msg.split('\n'):
                    LOG.error(line)
                    raise exc.HTTPBadRequest(msg)

        for param in params:
            param_name = param['param-name']
            param_value = data.get(param_name, None)
            # If the parameter wasn't found and it was required, return 400
            if param_value is None and param['required']:
                msg = ("Failed to parse request. " +
                       "Parameter: " + param_name + " not specified")
                for line in msg.split('\n'):
                    LOG.error(line)
                raise exc.HTTPBadRequest(msg)
            results[param_name] = param_value or param.get('default-value')

        return results

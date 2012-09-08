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


LOG = logging.getLogger(__name__)


class QuantumController(object):
    """ Base controller class for Quantum API """
    # _resource_name will be redefined in sub concrete controller
    _resource_name = None

    def __init__(self, plugin):
        self._plugin = plugin
        super(QuantumController, self).__init__()

    def _prepare_request_body(self, body, params):
        """ verifies required parameters are in request body.
            sets default value for missing optional parameters.

            body argument must be the deserialized body
        """
        try:
            if body is None:
                # Initialize empty resource for setting default value
                body = {self._resource_name: {}}
            data = body[self._resource_name]
        except KeyError:
            # raise if _resource_name is not in req body.
            raise exc.HTTPBadRequest("Unable to find '%s' in request body"
                                     % self._resource_name)
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
            data[param_name] = param_value or param.get('default-value')
        return body

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

import logging

from webob import exc

from quantum.api import api_common as common
from quantum.api import faults
from quantum.api.views import attachments as attachments_view
from quantum.common import exceptions as exception

LOG = logging.getLogger('quantum.api.ports')


class Controller(common.QuantumController):
    """ Port API controller for Quantum API """

    _attachment_ops_param_list = [{
        'param-name': 'id',
        'required': True}, ]

    _serialization_metadata = {
        "application/xml": {
            "attributes": {
                "attachment": ["id"], }
        },
    }

    def __init__(self, plugin):
        self._resource_name = 'attachment'
        super(Controller, self).__init__(plugin)

    def get_resource(self, request, tenant_id, network_id, id):
        try:
            att_data = self._plugin.get_port_details(
                            tenant_id, network_id, id)
            builder = attachments_view.get_view_builder(request)
            result = builder.build(att_data)['attachment']
            return dict(attachment=result)
        except exception.NetworkNotFound as e:
            return faults.Fault(faults.NetworkNotFound(e))
        except exception.PortNotFound as e:
            return faults.Fault(faults.PortNotFound(e))

    def attach_resource(self, request, tenant_id, network_id, id):
        try:
            request_params = \
                self._parse_request_params(request,
                                           self._attachment_ops_param_list)
        except exc.HTTPError as e:
            return faults.Fault(e)
        try:
            LOG.debug("PLUGGING INTERFACE:%s", request_params['id'])
            self._plugin.plug_interface(tenant_id, network_id, id,
                                        request_params['id'])
            return exc.HTTPNoContent()
        except exception.NetworkNotFound as e:
            return faults.Fault(faults.NetworkNotFound(e))
        except exception.PortNotFound as e:
            return faults.Fault(faults.PortNotFound(e))
        except exception.PortInUse as e:
            return faults.Fault(faults.PortInUse(e))
        except exception.AlreadyAttached as e:
            return faults.Fault(faults.AlreadyAttached(e))

    def detach_resource(self, request, tenant_id, network_id, id):
        try:
            self._plugin.unplug_interface(tenant_id,
                                          network_id, id)
            return exc.HTTPNoContent()
        except exception.NetworkNotFound as e:
            return faults.Fault(faults.NetworkNotFound(e))
        except exception.PortNotFound as e:
            return faults.Fault(faults.PortNotFound(e))

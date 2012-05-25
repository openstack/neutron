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

from quantum.api import api_common as common
from quantum.api.views import attachments as attachments_view
from quantum.common import exceptions as exception


LOG = logging.getLogger(__name__)


def create_resource(plugin, version):
    controller_dict = {
        '1.0': [ControllerV10(plugin),
                ControllerV10._serialization_metadata,
                common.XML_NS_V10],
        '1.1': [ControllerV11(plugin),
                ControllerV11._serialization_metadata,
                common.XML_NS_V11],
        }
    return common.create_resource(version, controller_dict)


class Controller(common.QuantumController):
    """ Port API controller for Quantum API """
    _resource_name = 'attachment'
    # version will be redefined by in child class
    version = None
    _attachment_ops_param_list = [
        {
            'param-name': 'id',
            'required': True,
            },
        ]

    _serialization_metadata = {
        "application/xml": {
            "attributes": {
                "attachment": ["id"],
                },
            },
        }

    @common.APIFaultWrapper([exception.NetworkNotFound,
                             exception.PortNotFound])
    def get_resource(self, request, tenant_id, network_id, id):
        att_data = self._plugin.get_port_details(tenant_id, network_id, id)
        builder = attachments_view.get_view_builder(request)
        result = builder.build(att_data)['attachment']
        return dict(attachment=result)

    @common.APIFaultWrapper([exception.NetworkNotFound,
                             exception.PortNotFound,
                             exception.PortInUse,
                             exception.AlreadyAttached])
    def attach_resource(self, request, tenant_id, network_id, id, body):
        body = self._prepare_request_body(body,
                                          self._attachment_ops_param_list)
        self._plugin.plug_interface(tenant_id, network_id, id,
                                    body['attachment']['id'])

    @common.APIFaultWrapper([exception.NetworkNotFound,
                             exception.PortNotFound])
    def detach_resource(self, request, tenant_id, network_id, id):
        self._plugin.unplug_interface(tenant_id, network_id, id)


class ControllerV10(Controller):
    """Attachment resources controller for Quantum v1.0 API"""
    version = "1.0"


class ControllerV11(Controller):
    """Attachment resources controller for Quantum v1.1 API"""
    version = "1.1"

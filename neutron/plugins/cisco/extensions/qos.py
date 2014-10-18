# Copyright 2011 Cisco Systems, Inc.
# All rights reserved.
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

from webob import exc

from neutron.api import api_common as common
from neutron.api import extensions
from neutron import manager
from neutron.plugins.cisco.common import cisco_exceptions as exception
from neutron.plugins.cisco.common import cisco_faults as faults
from neutron.plugins.cisco.extensions import _qos_view as qos_view
from neutron import wsgi


class Qos(extensions.ExtensionDescriptor):
    """Qos extension file."""

    @classmethod
    def get_name(cls):
        """Returns Ext Resource Name."""
        return "Cisco qos"

    @classmethod
    def get_alias(cls):
        """Returns Ext Resource Alias."""
        return "Cisco qos"

    @classmethod
    def get_description(cls):
        """Returns Ext Resource Description."""
        return "qos includes qos_name and qos_desc"

    @classmethod
    def get_namespace(cls):
        """Returns Ext Resource Namespace."""
        return "http://docs.ciscocloud.com/api/ext/qos/v1.0"

    @classmethod
    def get_updated(cls):
        """Returns Ext Resource update."""
        return "2011-07-25T13:25:27-06:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        parent_resource = dict(member_name="tenant",
                               collection_name="extensions/csco/tenants")

        controller = QosController(manager.NeutronManager.get_plugin())
        return [extensions.ResourceExtension('qoss', controller,
                                             parent=parent_resource)]


class QosController(common.NeutronController, wsgi.Controller):
    """qos API controller based on NeutronController."""

    _qos_ops_param_list = [
        {'param-name': 'qos_name', 'required': True},
        {'param-name': 'qos_desc', 'required': True},
    ]

    _serialization_metadata = {
        "application/xml": {
            "attributes": {
                "qos": ["id", "name"],
            },
        },
    }

    def __init__(self, plugin):
        self._resource_name = 'qos'
        self._plugin = plugin

    def index(self, request, tenant_id):
        """Returns a list of qos ids."""
        return self._items(request, tenant_id, is_detail=False)

    def _items(self, request, tenant_id, is_detail):
        """Returns a list of qoss."""
        qoss = self._plugin.get_all_qoss(tenant_id)
        builder = qos_view.get_view_builder(request)
        result = [builder.build(qos, is_detail)['qos'] for qos in qoss]
        return dict(qoss=result)

    # pylint: disable=no-member
    def show(self, request, tenant_id, id):
        """Returns qos details for the given qos id."""
        try:
            qos = self._plugin.get_qos_details(tenant_id, id)
            builder = qos_view.get_view_builder(request)
            #build response with details
            result = builder.build(qos, True)
            return dict(qoss=result)
        except exception.QosNotFound as exp:
            return faults.Fault(faults.QosNotFound(exp))

    def create(self, request, tenant_id):
        """Creates a new qos for a given tenant."""
        #look for qos name in request
        try:
            body = self._deserialize(request.body, request.get_content_type())
            req_body = self._prepare_request_body(body,
                                                  self._qos_ops_param_list)
            req_params = req_body[self._resource_name]
        except exc.HTTPError as exp:
            return faults.Fault(exp)
        qos = self._plugin.create_qos(tenant_id,
                                      req_params['qos_name'],
                                      req_params['qos_desc'])
        builder = qos_view.get_view_builder(request)
        result = builder.build(qos)
        return dict(qoss=result)

    def update(self, request, tenant_id, id):
        """Updates the name for the qos with the given id."""
        try:
            body = self._deserialize(request.body, request.get_content_type())
            req_body = self._prepare_request_body(body,
                                                  self._qos_ops_param_list)
            req_params = req_body[self._resource_name]
        except exc.HTTPError as exp:
            return faults.Fault(exp)
        try:
            qos = self._plugin.rename_qos(tenant_id, id,
                                          req_params['qos_name'])

            builder = qos_view.get_view_builder(request)
            result = builder.build(qos, True)
            return dict(qoss=result)
        except exception.QosNotFound as exp:
            return faults.Fault(faults.QosNotFound(exp))

    def delete(self, request, tenant_id, id):
        """Destroys the qos with the given id."""
        try:
            self._plugin.delete_qos(tenant_id, id)
            return exc.HTTPOk()
        except exception.QosNotFound as exp:
            return faults.Fault(faults.QosNotFound(exp))

"""
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
# @author: Ying Liu, Cisco Systems, Inc.
#
"""
import logging

from webob import exc

from quantum.api import api_common as common
from quantum.api.views import ports as port_view
from quantum.extensions import extensions
from quantum.manager import QuantumManager
from quantum.plugins.cisco.common import cisco_exceptions as exception
from quantum.plugins.cisco.common import cisco_faults as faults

LOG = logging.getLogger('quantum.api.multiports')


class Multiport(object):
    """extension class multiport"""
    def __init__(self):
        pass

    @classmethod
    def get_name(cls):
        """ Returns Ext Resource Name """
        return "Cisco Multiport"

    @classmethod
    def get_alias(cls):
        """ Returns Ext Resource Alias """
        return "Cisco Multiport"

    @classmethod
    def get_description(cls):
        """ Returns Ext Resource Description """
        return "handle multiple ports in one call"

    @classmethod
    def get_namespace(cls):
        """ Returns Ext Resource Namespace """
        return "http://docs.ciscocloud.com/api/ext/multiport/v1.0"

    @classmethod
    def get_updated(cls):
        """ Returns Ext Resource Update Time """
        return "2011-08-25T13:25:27-06:00"

    @classmethod
    def get_resources(cls):
        """ Returns Ext Resources """
        parent_resource = dict(member_name="tenant",
                               collection_name="extensions/csco/tenants")
        controller = MultiportController(QuantumManager.get_plugin())
        return [extensions.ResourceExtension('multiport', controller,
                                             parent=parent_resource)]


class MultiportController(common.QuantumController):
    """ multiport API controller
        based on QuantumController """

    _multiport_ops_param_list = [{
        'param-name': 'net_id_list',
        'required': True}, {
        'param-name': 'status',
        'required': True}, {
        'param-name': 'ports_desc',
        'required': True}]

    _serialization_metadata = {
        "application/xml": {
            "attributes": {
                "multiport": ["id", "name"],
            },
        },
    }

    def __init__(self, plugin):
        self._resource_name = 'multiport'
        self._plugin = plugin

    # pylint: disable-msg=E1101,W0613
    def create(self, request, tenant_id):
        """ Creates a new multiport for a given tenant """
        try:
            req_params = \
                self._parse_request_params(request,
                                           self._multiport_ops_param_list)
        except exc.HTTPError as exp:
            return faults.Fault(exp)
        multiports = self._plugin.\
                       create_multiport(tenant_id,
                                          req_params['net_id_list'],
                                          req_params['status'],
                                          req_params['ports_desc'])
        builder = port_view.get_view_builder(request)
        result = [builder.build(port)['port']
                      for port in multiports]
        return dict(ports=result)

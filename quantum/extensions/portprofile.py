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

from webob import exc

from quantum.extensions import _pprofiles as pprofiles_view
from quantum.api import api_common as common
from quantum.common import exceptions as qexception
from quantum.extensions import extensions
from quantum.manager import QuantumManager
from quantum.plugins.cisco.common import cisco_exceptions as exception
from quantum.plugins.cisco.common import cisco_faults as faults


class Portprofile(object):
    """extension class Portprofile"""
    def __init__(self):
        pass

    @classmethod
    def get_name(cls):
        """ Returns Ext Resource Name """
        return "Cisco Port Profile"

    @classmethod
    def get_alias(cls):
        """ Returns Ext Resource alias """
        return "Cisco Port Profile"

    @classmethod
    def get_description(cls):
        """ Returns Ext Resource Description """
        return "Portprofile include QoS information"

    @classmethod
    def get_namespace(cls):
        """ Returns Ext Resource Namespace """
        return "http://docs.ciscocloud.com/api/ext/portprofile/v1.0"

    @classmethod
    def get_updated(cls):
        """ Returns Ext Resource Updated time """
        return "2011-07-23T13:25:27-06:00"

    @classmethod
    def get_resources(cls):
        """ Returns all defined resources """
        parent_resource = dict(member_name="tenant",
                               collection_name="extensions/csco/tenants")
        member_actions = {'associate_portprofile': "PUT",
                          'disassociate_portprofile': "PUT"}
        controller = PortprofilesController(QuantumManager.get_plugin())
        return [extensions.ResourceExtension('portprofiles', controller,
                                             parent=parent_resource,
                                             member_actions=member_actions)]


class PortprofilesController(common.QuantumController):
    """ portprofile API controller
        based on QuantumController """

    def __init__(self, plugin):
        self._resource_name = 'portprofile'
        self._plugin = plugin

        self._portprofile_ops_param_list = [{
        'param-name': 'portprofile_name',
        'required': True}, {
        'param-name': 'qos_name',
        'required': True}, {
        'param-name': 'assignment',
        'required': False}]

        self._assignprofile_ops_param_list = [{
        'param-name': 'network-id',
        'required': True}, {
        'param-name': 'port-id',
        'required': True}]

        self._serialization_metadata = {
        "application/xml": {
            "attributes": {
                "portprofile": ["id", "name"],
            },
        },
    }

    def index(self, request, tenant_id):
        """ Returns a list of portprofile ids """
        return self._items(request, tenant_id, is_detail=False)

    def _items(self, request, tenant_id, is_detail):
        """ Returns a list of portprofiles. """
        portprofiles = self._plugin.get_all_portprofiles(tenant_id)
        builder = pprofiles_view.get_view_builder(request)
        result = [builder.build(portprofile, is_detail)['portprofile']
                  for portprofile in portprofiles]
        return dict(portprofiles=result)

    # pylint: disable-msg=E1101
    def show(self, request, tenant_id, id):
        """ Returns portprofile details for the given portprofile id """
        try:
            portprofile = self._plugin.get_portprofile_details(
                            tenant_id, id)
            builder = pprofiles_view.get_view_builder(request)
            #build response with details
            result = builder.build(portprofile, True)
            return dict(portprofiles=result)
        except exception.PortProfileNotFound as exp:
            return faults.Fault(faults.PortprofileNotFound(exp))

    def create(self, request, tenant_id):
        """ Creates a new portprofile for a given tenant """
        #look for portprofile name in request
        try:
            req_params = \
                self._parse_request_params(request,
                                           self._portprofile_ops_param_list)
        except exc.HTTPError as exp:
            return faults.Fault(exp)
        portprofile = self._plugin.\
                       create_portprofile(tenant_id,
                                          req_params['portprofile_name'],
                                          req_params['qos_name'])
        builder = pprofiles_view.get_view_builder(request)
        result = builder.build(portprofile)
        return dict(portprofiles=result)

    def update(self, request, tenant_id, id):
        """ Updates the name for the portprofile with the given id """
        try:
            req_params = \
                self._parse_request_params(request,
                                           self._portprofile_ops_param_list)
        except exc.HTTPError as exp:
            return faults.Fault(exp)
        try:
            portprofile = self._plugin.\
            rename_portprofile(tenant_id,
                        id, req_params['portprofile_name'])

            builder = pprofiles_view.get_view_builder(request)
            result = builder.build(portprofile, True)
            return dict(portprofiles=result)
        except exception.PortProfileNotFound as exp:
            return faults.Fault(faults.PortprofileNotFound(exp))

    def delete(self, request, tenant_id, id):
        """ Destroys the portprofile with the given id """
        try:
            self._plugin.delete_portprofile(tenant_id, id)
            return exc.HTTPOk()
        except exception.PortProfileNotFound as exp:
            return faults.Fault(faults.PortprofileNotFound(exp))

    def associate_portprofile(self, request, tenant_id, id):
        """ associate a portprofile to the port """
        content_type = request.best_match_content_type()

        try:
            req_params = \
                self._parse_request_params(request,
                                           self._assignprofile_ops_param_list)
        except exc.HTTPError as exp:
            return faults.Fault(exp)
        net_id = req_params['network-id'].strip()
        port_id = req_params['port-id'].strip()
        try:
            self._plugin.associate_portprofile(tenant_id,
                                                net_id, port_id,
                                                id)
            return exc.HTTPOk()
        except exception.PortProfileNotFound as exp:
            return faults.Fault(faults.PortprofileNotFound(exp))
        except qexception.PortNotFound as exp:
            return faults.Fault(faults.PortNotFound(exp))

    def disassociate_portprofile(self, request, tenant_id, id):
        """ Disassociate a portprofile from a port """
        content_type = request.best_match_content_type()
        try:
            req_params = \
                self._parse_request_params(request,
                                           self._assignprofile_ops_param_list)
        except exc.HTTPError as exp:
            return faults.Fault(exp)
        net_id = req_params['network-id'].strip()
        port_id = req_params['port-id'].strip()
        try:
            self._plugin. \
            disassociate_portprofile(tenant_id,
                                    net_id, port_id, id)
            return exc.HTTPOk()
        except exception.PortProfileNotFound as exp:
            return faults.Fault(faults.PortprofileNotFound(exp))
        except qexception.PortNotFound as exp:
            return faults.Fault(faults.PortNotFound(exp))

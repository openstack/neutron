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

from quantum.extensions import _credential_view as credential_view
from quantum.api import api_common as common
from quantum.extensions import extensions
from quantum.manager import QuantumManager
from quantum.plugins.cisco.common import cisco_exceptions as exception
from quantum.plugins.cisco.common import cisco_faults as faults

LOG = logging.getLogger('quantum.api.credentials')


class Credential(object):
    """extension class Credential"""
    def __init__(self):
        pass

    @classmethod
    def get_name(cls):
        """ Returns Ext Resource Name """
        return "Cisco Credential"

    @classmethod
    def get_alias(cls):
        """ Returns Ext Resource Alias """
        return "Cisco Credential"

    @classmethod
    def get_description(cls):
        """ Returns Ext Resource Description """
        return "Credential include username and password"

    @classmethod
    def get_namespace(cls):
        """ Returns Ext Resource Namespace """
        return "http://docs.ciscocloud.com/api/ext/credential/v1.0"

    @classmethod
    def get_updated(cls):
        """ Returns Ext Resource Update Time """
        return "2011-07-25T13:25:27-06:00"

    @classmethod
    def get_resources(cls):
        """ Returns Ext Resources """
        parent_resource = dict(member_name="tenant",
                               collection_name="extensions/csco/tenants")
        controller = CredentialController(QuantumManager.get_plugin())
        return [extensions.ResourceExtension('credentials', controller,
                                             parent=parent_resource)]


class CredentialController(common.QuantumController):
    """ credential API controller
        based on QuantumController """

    _credential_ops_param_list = [{
        'param-name': 'credential_name',
        'required': True}, {
        'param-name': 'user_name',
        'required': True}, {
        'param-name': 'password',
        'required': True}]

    _serialization_metadata = {
        "application/xml": {
            "attributes": {
                "credential": ["id", "name"],
            },
        },
    }

    def __init__(self, plugin):
        self._resource_name = 'credential'
        self._plugin = plugin

    def index(self, request, tenant_id):
        """ Returns a list of credential ids """
        return self._items(request, tenant_id, is_detail=False)

    def _items(self, request, tenant_id, is_detail):
        """ Returns a list of credentials. """
        credentials = self._plugin.get_all_credentials(tenant_id)
        builder = credential_view.get_view_builder(request)
        result = [builder.build(credential, is_detail)['credential']
                  for credential in credentials]
        return dict(credentials=result)

    # pylint: disable-msg=E1101,W0613
    def show(self, request, tenant_id, id):
        """ Returns credential details for the given credential id """
        try:
            credential = self._plugin.get_credential_details(
                            tenant_id, id)
            builder = credential_view.get_view_builder(request)
            #build response with details
            result = builder.build(credential, True)
            return dict(credentials=result)
        except exception.CredentialNotFound as exp:
            return faults.Fault(faults.CredentialNotFound(exp))

    def create(self, request, tenant_id):
        """ Creates a new credential for a given tenant """
        try:
            req_params = \
                self._parse_request_params(request,
                                           self._credential_ops_param_list)
        except exc.HTTPError as exp:
            return faults.Fault(exp)
        credential = self._plugin.\
                       create_credential(tenant_id,
                                          req_params['credential_name'],
                                          req_params['user_name'],
                                          req_params['password'])
        builder = credential_view.get_view_builder(request)
        result = builder.build(credential)
        return dict(credentials=result)

    def update(self, request, tenant_id, id):
        """ Updates the name for the credential with the given id """
        try:
            req_params = \
                self._parse_request_params(request,
                                           self._credential_ops_param_list)
        except exc.HTTPError as exp:
            return faults.Fault(exp)
        try:
            credential = self._plugin.\
            rename_credential(tenant_id,
                        id, req_params['credential_name'])

            builder = credential_view.get_view_builder(request)
            result = builder.build(credential, True)
            return dict(credentials=result)
        except exception.CredentialNotFound as exp:
            return faults.Fault(faults.CredentialNotFound(exp))

    def delete(self, request, tenant_id, id):
        """ Destroys the credential with the given id """
        try:
            self._plugin.delete_credential(tenant_id, id)
            return exc.HTTPOk()
        except exception.CredentialNotFound as exp:
            return faults.Fault(faults.CredentialNotFound(exp))

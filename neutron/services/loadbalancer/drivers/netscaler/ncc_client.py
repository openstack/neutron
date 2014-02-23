# Copyright 2014 Citrix Systems
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
import requests

from neutron.common import exceptions as n_exc
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

CONTENT_TYPE_HEADER = 'Content-type'
ACCEPT_HEADER = 'Accept'
AUTH_HEADER = 'Authorization'
DRIVER_HEADER = 'X-OpenStack-LBaaS'
TENANT_HEADER = 'X-Tenant-ID'
JSON_CONTENT_TYPE = 'application/json'
DRIVER_HEADER_VALUE = 'netscaler-openstack-lbaas'


class NCCException(n_exc.NeutronException):

    """Represents exceptions thrown by NSClient."""

    CONNECTION_ERROR = 1
    REQUEST_ERROR = 2
    RESPONSE_ERROR = 3
    UNKNOWN_ERROR = 4

    def __init__(self, error):
        self.message = _("NCC Error %d") % error
        super(NCCException, self).__init__()
        self.error = error


class NSClient(object):

    """Client to operate on REST resources of NetScaler Control Center."""

    def __init__(self, service_uri, username, password):
        if not service_uri:
            msg = _("No NetScaler Control Center URI specified. "
                    "Cannot connect.")
            LOG.exception(msg)
            raise NCCException(NCCException.CONNECTION_ERROR)
        self.service_uri = service_uri.strip('/')
        self.auth = None
        if username and password:
            base64string = base64.encodestring("%s:%s" % (username, password))
            base64string = base64string[:-1]
            self.auth = 'Basic %s' % base64string

    def create_resource(self, tenant_id, resource_path, object_name,
                        object_data):
        """Create a resource of NetScaler Control Center."""
        return self._resource_operation('POST', tenant_id,
                                        resource_path,
                                        object_name=object_name,
                                        object_data=object_data)

    def retrieve_resource(self, tenant_id, resource_path, parse_response=True):
        """Retrieve a resource of NetScaler Control Center."""
        return self._resource_operation('GET', tenant_id, resource_path)

    def update_resource(self, tenant_id, resource_path, object_name,
                        object_data):
        """Update a resource of the NetScaler Control Center."""
        return self._resource_operation('PUT', tenant_id,
                                        resource_path,
                                        object_name=object_name,
                                        object_data=object_data)

    def remove_resource(self, tenant_id, resource_path, parse_response=True):
        """Remove a resource of NetScaler Control Center."""
        return self._resource_operation('DELETE', tenant_id, resource_path)

    def _resource_operation(self, method, tenant_id, resource_path,
                            object_name=None, object_data=None):
        resource_uri = "%s/%s" % (self.service_uri, resource_path)
        headers = self._setup_req_headers(tenant_id)
        request_body = None
        if object_data:
            if isinstance(object_data, str):
                request_body = object_data
            else:
                obj_dict = {object_name: object_data}
                request_body = jsonutils.dumps(obj_dict)

        response_status, resp_dict = self._execute_request(method,
                                                           resource_uri,
                                                           headers,
                                                           body=request_body)
        return response_status, resp_dict

    def _is_valid_response(self, response_status):
        # when status is less than 400, the response is fine
        return response_status < requests.codes.bad_request

    def _setup_req_headers(self, tenant_id):
        headers = {ACCEPT_HEADER: JSON_CONTENT_TYPE,
                   CONTENT_TYPE_HEADER: JSON_CONTENT_TYPE,
                   DRIVER_HEADER: DRIVER_HEADER_VALUE,
                   TENANT_HEADER: tenant_id,
                   AUTH_HEADER: self.auth}
        return headers

    def _get_response_dict(self, response):
        response_dict = {'status': response.status_code,
                         'body': response.text,
                         'headers': response.headers}
        if self._is_valid_response(response.status_code):
            if response.text:
                response_dict['dict'] = response.json()
        return response_dict

    def _execute_request(self, method, resource_uri, headers, body=None):
        try:
            response = requests.request(method, url=resource_uri,
                                        headers=headers, data=body)
        except requests.exceptions.ConnectionError:
            msg = (_("Connection error occurred while connecting to %s") %
                   self.service_uri)
            LOG.exception(msg)
            raise NCCException(NCCException.CONNECTION_ERROR)
        except requests.exceptions.SSLError:
            msg = (_("SSL error occurred while connecting to %s") %
                   self.service_uri)
            LOG.exception(msg)
            raise NCCException(NCCException.CONNECTION_ERROR)
        except requests.exceptions.Timeout:
            msg = _("Request to %s timed out") % self.service_uri
            LOG.exception(msg)
            raise NCCException(NCCException.CONNECTION_ERROR)
        except (requests.exceptions.URLRequired,
                requests.exceptions.InvalidURL,
                requests.exceptions.MissingSchema,
                requests.exceptions.InvalidSchema):
            msg = _("Request did not specify a valid URL")
            LOG.exception(msg)
            raise NCCException(NCCException.REQUEST_ERROR)
        except requests.exceptions.TooManyRedirects:
            msg = _("Too many redirects occurred for request to %s")
            LOG.exception(msg)
            raise NCCException(NCCException.REQUEST_ERROR)
        except requests.exceptions.RequestException:
            msg = (_("A request error while connecting to %s") %
                   self.service_uri)
            LOG.exception(msg)
            raise NCCException(NCCException.REQUEST_ERROR)
        except Exception:
            msg = (_("A unknown error occurred during request to %s") %
                   self.service_uri)
            LOG.exception(msg)
            raise NCCException(NCCException.UNKNOWN_ERROR)
        resp_dict = self._get_response_dict(response)
        LOG.debug(_("Response: %s"), resp_dict['body'])
        response_status = resp_dict['status']
        if response_status == requests.codes.unauthorized:
            LOG.exception(_("Unable to login. Invalid credentials passed."
                          "for: %s"), self.service_uri)
            raise NCCException(NCCException.RESPONSE_ERROR)
        if not self._is_valid_response(response_status):
            msg = (_("Failed %(method)s operation on %(url)s "
                   "status code: %(response_status)s") %
                   {"method": method,
                    "url": resource_uri,
                    "response_status": response_status})
            LOG.exception(msg)
            raise NCCException(NCCException.RESPONSE_ERROR)
        return response_status, resp_dict

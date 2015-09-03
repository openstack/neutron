# Copyright 2015 NEC Corporation.  All rights reserved.
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

from tempest_lib.common import rest_client

from neutron.tests.tempest import config

CONF = config.CONF


class ServiceClient(rest_client.RestClient):

    def __init__(self, auth_provider, service, region,
                 endpoint_type=None, build_interval=None, build_timeout=None,
                 disable_ssl_certificate_validation=None, ca_certs=None,
                 trace_requests=None):

        # TODO(oomichi): This params setting should be removed after all
        # service clients pass these values, and we can make ServiceClient
        # free from CONF values.
        dscv = (disable_ssl_certificate_validation or
                CONF.identity.disable_ssl_certificate_validation)
        params = {
            'disable_ssl_certificate_validation': dscv,
            'ca_certs': ca_certs or CONF.identity.ca_certificates_file,
            'trace_requests': trace_requests or CONF.debug.trace_requests
        }

        if endpoint_type is not None:
            params.update({'endpoint_type': endpoint_type})
        if build_interval is not None:
            params.update({'build_interval': build_interval})
        if build_timeout is not None:
            params.update({'build_timeout': build_timeout})
        super(ServiceClient, self).__init__(auth_provider, service, region,
                                            **params)


class ResponseBody(dict):
    """Class that wraps an http response and dict body into a single value.

    Callers that receive this object will normally use it as a dict but
    can extract the response if needed.
    """

    def __init__(self, response, body=None):
        body_data = body or {}
        self.update(body_data)
        self.response = response

    def __str__(self):
        body = super(ResponseBody, self).__str__()
        return "response: %s\nBody: %s" % (self.response, body)


class ResponseBodyData(object):
    """Class that wraps an http response and string data into a single value.
    """

    def __init__(self, response, data):
        self.response = response
        self.data = data

    def __str__(self):
        return "response: %s\nBody: %s" % (self.response, self.data)


class ResponseBodyList(list):
    """Class that wraps an http response and list body into a single value.

    Callers that receive this object will normally use it as a list but
    can extract the response if needed.
    """

    def __init__(self, response, body=None):
        body_data = body or []
        self.extend(body_data)
        self.response = response

    def __str__(self):
        body = super(ResponseBodyList, self).__str__()
        return "response: %s\nBody: %s" % (self.response, body)

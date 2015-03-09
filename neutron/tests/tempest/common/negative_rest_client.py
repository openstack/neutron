# (c) 2014 Deutsche Telekom AG
# Copyright 2014 Red Hat, Inc.
# Copyright 2014 NEC Corporation
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

from neutron.tests.tempest.common import service_client
from neutron.tests.tempest import config

CONF = config.CONF


class NegativeRestClient(service_client.ServiceClient):
    """
    Version of RestClient that does not raise exceptions.
    """
    def __init__(self, auth_provider, service):
        region = self._get_region(service)
        super(NegativeRestClient, self).__init__(auth_provider,
                                                 service, region)

    def _get_region(self, service):
        """
        Returns the region for a specific service
        """
        service_region = None
        for cfgname in dir(CONF._config):
            # Find all config.FOO.catalog_type and assume FOO is a service.
            cfg = getattr(CONF, cfgname)
            catalog_type = getattr(cfg, 'catalog_type', None)
            if catalog_type == service:
                service_region = getattr(cfg, 'region', None)
        if not service_region:
            service_region = CONF.identity.region
        return service_region

    def _error_checker(self, method, url,
                       headers, body, resp, resp_body):
        pass

    def send_request(self, method, url_template, resources, body=None):
        url = url_template % tuple(resources)
        if method == "GET":
            resp, body = self.get(url)
        elif method == "POST":
            resp, body = self.post(url, body)
        elif method == "PUT":
            resp, body = self.put(url, body)
        elif method == "PATCH":
            resp, body = self.patch(url, body)
        elif method == "HEAD":
            resp, body = self.head(url)
        elif method == "DELETE":
            resp, body = self.delete(url)
        elif method == "COPY":
            resp, body = self.copy(url)
        else:
            assert False

        return resp, body

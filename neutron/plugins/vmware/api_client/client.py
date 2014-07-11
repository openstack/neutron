# Copyright 2012 VMware, Inc.
#
# All Rights Reserved
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

import httplib

from neutron.openstack.common import log as logging
from neutron.plugins.vmware.api_client import base
from neutron.plugins.vmware.api_client import eventlet_client
from neutron.plugins.vmware.api_client import eventlet_request
from neutron.plugins.vmware.api_client import exception
from neutron.plugins.vmware.api_client import version

LOG = logging.getLogger(__name__)


class NsxApiClient(eventlet_client.EventletApiClient):
    """The Nsx API Client."""

    def __init__(self, api_providers, user, password,
                 concurrent_connections=base.DEFAULT_CONCURRENT_CONNECTIONS,
                 gen_timeout=base.GENERATION_ID_TIMEOUT,
                 use_https=True,
                 connect_timeout=base.DEFAULT_CONNECT_TIMEOUT,
                 http_timeout=75, retries=2, redirects=2):
        '''Constructor. Adds the following:

        :param http_timeout: how long to wait before aborting an
            unresponsive controller (and allow for retries to another
            controller in the cluster)
        :param retries: the number of concurrent connections.
        :param redirects: the number of concurrent connections.
        '''
        super(NsxApiClient, self).__init__(
            api_providers, user, password,
            concurrent_connections=concurrent_connections,
            gen_timeout=gen_timeout, use_https=use_https,
            connect_timeout=connect_timeout)

        self._request_timeout = http_timeout * retries
        self._http_timeout = http_timeout
        self._retries = retries
        self._redirects = redirects
        self._version = None

    # NOTE(salvatore-orlando): This method is not used anymore. Login is now
    # performed automatically inside the request eventlet if necessary.
    def login(self, user=None, password=None):
        '''Login to NSX controller.

        Assumes same password is used for all controllers.

        :param user: controller user (usually admin). Provided for
                backwards compatibility. In the  normal mode of operation
                this should be None.
        :param password: controller password. Provided for backwards
                compatibility. In the normal mode of operation this should
                be None.
        '''
        if user:
            self._user = user
        if password:
            self._password = password

        return self._login()

    def request(self, method, url, body="", content_type="application/json"):
        '''Issues request to controller.'''

        g = eventlet_request.GenericRequestEventlet(
            self, method, url, body, content_type, auto_login=True,
            http_timeout=self._http_timeout,
            retries=self._retries, redirects=self._redirects)
        g.start()
        response = g.join()
        LOG.debug(_('Request returns "%s"'), response)

        # response is a modified HTTPResponse object or None.
        # response.read() will not work on response as the underlying library
        # request_eventlet.ApiRequestEventlet has already called this
        # method in order to extract the body and headers for processing.
        # ApiRequestEventlet derived classes call .read() and
        # .getheaders() on the HTTPResponse objects and store the results in
        # the response object's .body and .headers data members for future
        # access.

        if response is None:
            # Timeout.
            LOG.error(_('Request timed out: %(method)s to %(url)s'),
                      {'method': method, 'url': url})
            raise exception.RequestTimeout()

        status = response.status
        if status == httplib.UNAUTHORIZED:
            raise exception.UnAuthorizedRequest()

        # Fail-fast: Check for exception conditions and raise the
        # appropriate exceptions for known error codes.
        if status in exception.ERROR_MAPPINGS:
            LOG.error(_("Received error code: %s"), status)
            LOG.error(_("Server Error Message: %s"), response.body)
            exception.ERROR_MAPPINGS[status](response)

        # Continue processing for non-error condition.
        if (status != httplib.OK and status != httplib.CREATED
                and status != httplib.NO_CONTENT):
            LOG.error(_("%(method)s to %(url)s, unexpected response code: "
                        "%(status)d (content = '%(body)s')"),
                      {'method': method, 'url': url,
                       'status': response.status, 'body': response.body})
            return None

        if not self._version:
            self._version = version.find_version(response.headers)
        return response.body

    def get_version(self):
        if not self._version:
            # Determine the controller version by querying the
            # cluster nodes. Currently, the version will be the
            # one of the server that responds.
            self.request('GET', '/ws.v1/control-cluster/node')
            if not self._version:
                LOG.error(_('Unable to determine NSX version. '
                          'Plugin might not work as expected.'))
        return self._version

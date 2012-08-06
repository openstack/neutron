# Copyright 2012 Nicira, Inc.
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
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Somik Behera, Nicira Networks, Inc.

import httplib  # basic HTTP library for HTTPS connections
import logging
from quantum.plugins.nicira.nicira_nvp_plugin.api_client import (
    client_eventlet, request_eventlet)

LOG = logging.getLogger("NVPApiHelper")
LOG.setLevel(logging.INFO)


class NVPApiHelper(client_eventlet.NvpApiClientEventlet):
    '''
    Helper class to do basic login, cookie management, and provide base
    method to send HTTP requests.

    Implements new eventlet-based framework derived from the management
    console nvp_gevent_client module.
    '''

    def __init__(self, api_providers, user, password, request_timeout,
                 http_timeout, retries, redirects, failover_time,
                 concurrent_connections=3):
        '''Constructor.

        :param api_providers: a list of tuples in the form:
            (host, port, is_ssl=True). Passed on to NvpClientEventlet.
        :param user: the login username.
        :param password: the login password.
        :param concurrent_connections: the number of concurrent connections.
        :param request_timeout: all operations (including retries, redirects
            from unresponsive controllers, etc) should finish within this
            timeout.
        :param http_timeout: how long to wait before aborting an
            unresponsive controller (and allow for retries to another
            controller in the cluster)
        :param retries: the number of concurrent connections.
        :param redirects: the number of concurrent connections.
        :param failover_time: minimum time between controller failover and new
            connections allowed.
        '''
        client_eventlet.NvpApiClientEventlet.__init__(
            self, api_providers, user, password, concurrent_connections,
            failover_time=failover_time)

        self._request_timeout = request_timeout
        self._http_timeout = http_timeout
        self._retries = retries
        self._redirects = redirects

    def login(self, user=None, password=None):
        '''Login to NVP controller.

        Assumes same password is used for all controllers.

        :param user: NVP controller user (usually admin). Provided for
                backwards compatability. In the  normal mode of operation
                this should be None.
        :param password: NVP controller password. Provided for backwards
                compatability. In the normal mode of operation this should
                be None.

        :returns: Does not return a value.
        '''
        if user:
            self._user = user
        if password:
            self._password = password

        return client_eventlet.NvpApiClientEventlet.login(self)

    def request(self, method, url, body="", content_type="application/json"):
        '''Issues request to controller.'''

        g = request_eventlet.NvpGenericRequestEventlet(
            self, method, url, body, content_type, auto_login=True,
            request_timeout=self._request_timeout,
            http_timeout=self._http_timeout,
            retries=self._retries, redirects=self._redirects)
        g.start()
        response = g.join()
        LOG.debug('NVPApiHelper.request() returns "%s"' % response)

        # response is a modified HTTPResponse object or None.
        # response.read() will not work on response as the underlying library
        # request_eventlet.NvpApiRequestEventlet has already called this
        # method in order to extract the body and headers for processing.
        # NvpApiRequestEventlet derived classes call .read() and
        # .getheaders() on the HTTPResponse objects and store the results in
        # the response object's .body and .headers data members for future
        # access.

        if response is None:
            # Timeout.
            LOG.error('Request timed out: %s to %s' % (method, url))
            raise RequestTimeout()

        status = response.status
        if status == httplib.UNAUTHORIZED:
            raise UnAuthorizedRequest()

        # Fail-fast: Check for exception conditions and raise the
        # appropriate exceptions for known error codes.
        if status in self.error_codes:
            LOG.error("Received error code: %s" % status)
            LOG.error("Server Error Message: %s" % response.body)
            self.error_codes[status](self)

        # Continue processing for non-error condition.
        if (status != httplib.OK and status != httplib.CREATED
                and status != httplib.NO_CONTENT):
            LOG.error("%s to %s, unexpected response code: %d (content = '%s')"
                      % (method, url, response.status, response.body))
            return None

        return response.body

    def fourZeroFour(self):
        raise ResourceNotFound()

    def fourZeroNine(self):
        raise Conflict()

    def fiveZeroThree(self):
        raise ServiceUnavailable()

    def fourZeroThree(self):
        raise Forbidden()

    def zero(self):
        raise NvpApiException()

    # TODO(del): ensure error_codes are handled/raised appropriately
    # in api_client.
    error_codes = {404: fourZeroFour,
                   409: fourZeroNine,
                   503: fiveZeroThree,
                   403: fourZeroThree,
                   301: zero,
                   307: zero,
                   400: zero,
                   500: zero,
                   503: zero}


class NvpApiException(Exception):
    '''
    Base NvpApiClient Exception

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.

    '''
    message = "An unknown exception occurred."

    def __init__(self, **kwargs):
        try:
            self._error_string = self.message % kwargs

        except Exception:
            # at least get the core message out if something happened
            self._error_string = self.message

    def __str__(self):
        return self._error_string


class UnAuthorizedRequest(NvpApiException):
    message = "Server denied session's authentication credentials."


class ResourceNotFound(NvpApiException):
    message = "An entity referenced in the request was not found."


class Conflict(NvpApiException):
    message = "Request conflicts with configuration on a different entity."


class ServiceUnavailable(NvpApiException):
    message = ("Request could not completed because the associated "
               "resource could not be reached.")


class Forbidden(NvpApiException):
    message = ("The request is forbidden from accessing the "
               "referenced resource.")


class RequestTimeout(NvpApiException):
    message = "The request has timed out."

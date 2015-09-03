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

import webob.dec

from neutron import wsgi


class Fault(webob.exc.HTTPException):
    """Error codes for API faults."""

    _fault_names = {
        400: "malformedRequest",
        401: "unauthorized",
        451: "CredentialNotFound",
        452: "QoSNotFound",
        453: "NovatenantNotFound",
        454: "MultiportNotFound",
        470: "serviceUnavailable",
        471: "pluginFault"
    }

    def __init__(self, exception):
        """Create a Fault for the given webob.exc.exception."""
        self.wrapped_exc = exception

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        """Generate a WSGI response.

        Response is generated based on the exception passed to constructor.
        """
        # Replace the body with fault details.
        code = self.wrapped_exc.status_int
        fault_name = self._fault_names.get(code, "neutronServiceFault")
        fault_data = {
            fault_name: {
                'code': code,
                'message': self.wrapped_exc.explanation}}
        # 'code' is an attribute on the fault tag itself
        content_type = req.best_match_content_type()
        self.wrapped_exc.body = wsgi.Serializer().serialize(
            fault_data, content_type)
        self.wrapped_exc.content_type = content_type
        return self.wrapped_exc


class PortNotFound(webob.exc.HTTPClientError):
    """PortNotFound exception.

    subclass of :class:`~HTTPClientError`

    This indicates that the server did not find the port specified
    in the HTTP request for a given network

    code: 430, title: Port not Found
    """
    code = 430
    title = _('Port not Found')
    explanation = _('Unable to find a port with the specified identifier.')


class CredentialNotFound(webob.exc.HTTPClientError):
    """CredentialNotFound exception.

    subclass of :class:`~HTTPClientError`

    This indicates that the server did not find the Credential specified
    in the HTTP request

    code: 451, title: Credential not Found
    """
    code = 451
    title = _('Credential Not Found')
    explanation = _('Unable to find a Credential with'
                    ' the specified identifier.')


class QosNotFound(webob.exc.HTTPClientError):
    """QosNotFound exception.

    subclass of :class:`~HTTPClientError`

    This indicates that the server did not find the QoS specified
    in the HTTP request

    code: 452, title: QoS not Found
    """
    code = 452
    title = _('QoS Not Found')
    explanation = _('Unable to find a QoS with'
                    ' the specified identifier.')


class NovatenantNotFound(webob.exc.HTTPClientError):
    """NovatenantNotFound exception.

    subclass of :class:`~HTTPClientError`

    This indicates that the server did not find the Novatenant specified
    in the HTTP request

    code: 453, title: Nova tenant not Found
    """
    code = 453
    title = _('Nova tenant Not Found')
    explanation = _('Unable to find a Novatenant with'
                    ' the specified identifier.')


class RequestedStateInvalid(webob.exc.HTTPClientError):
    """RequestedStateInvalid exception.

    subclass of :class:`~HTTPClientError`

    This indicates that the server could not update the port state
    to the request value

    code: 431, title: Requested State Invalid
    """
    code = 431
    title = _('Requested State Invalid')
    explanation = _('Unable to update port state with specified value.')

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Citrix Systems.
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


import webob.exc

from quantum.common import exceptions


_NETNOTFOUND_EXPL = 'Unable to find a network with the specified identifier.'
_NETINUSE_EXPL = 'Unable to remove the network: attachments still plugged.'
_PORTNOTFOUND_EXPL = 'Unable to find a port with the specified identifier.'
_STATEINVALID_EXPL = 'Unable to update port state with specified value.'
_PORTINUSE_EXPL = 'A resource is currently attached to the logical port'
_ALREADYATTACHED_EXPL = 'The resource is already attached to another port'
_NOTIMPLEMENTED_EXPL = 'Not implemented'


def fault_body_function_v10(wrapped_exc):
    """ This function creates the contents of the body for a fault
    response for Quantum API v1.0.

    :param wrapped_exc: Exception thrown by the Quantum service
    :type wrapped_exc: quantum.common.exceptions.QuantumException
    :returns: response body contents and serialization metadata
    :rtype: tuple
    """
    code = wrapped_exc.status_int
    fault_name = (hasattr(wrapped_exc, 'title') and
                  wrapped_exc.title or "quantumServiceFault")
    fault_data = {
        fault_name: {
            'code': code,
            'message': wrapped_exc.explanation,
            'detail': str(wrapped_exc.detail),
            },
        }
    metadata = {'attributes': {fault_name: ['code']}}
    return fault_data, metadata


def fault_body_function_v11(wrapped_exc):
    """ This function creates the contents of the body for a fault
    response for Quantum API v1.1.

    :param wrapped_exc: Exception thrown by the Quantum service
    :type wrapped_exc: quantum.common.exceptions.QuantumException
    :returns: response body contents and serialization metadata
    :rtype: tuple
    """
    fault_name = (hasattr(wrapped_exc, 'type') and
                  wrapped_exc.type or "QuantumServiceFault")
    # Ensure first letter is capital
    fault_name = fault_name[0].upper() + fault_name[1:]
    fault_data = {
        'QuantumError': {
            'type': fault_name,
            'message': wrapped_exc.explanation,
            'detail': str(wrapped_exc.detail),
            },
        }
    # Metadata not required for v11
    return fault_data, None


def fault_body_function(version):
    # dict mapping API version to functions for building the
    # fault response body
    fault_body_function_dict = {
        '1.0': fault_body_function_v10,
        '1.1': fault_body_function_v11
    }
    return fault_body_function_dict.get(version, None)


class Quantum10HTTPError(webob.exc.HTTPClientError):

    _fault_dict = {
            exceptions.NetworkNotFound: {
                'code': 420,
                'title': 'networkNotFound',
                'explanation': _NETNOTFOUND_EXPL
            },
            exceptions.NetworkInUse: {
                'code': 421,
                'title': 'networkInUse',
                'explanation': _NETINUSE_EXPL
            },
            exceptions.PortNotFound: {
                'code': 430,
                'title': 'portNotFound',
                'explanation': _PORTNOTFOUND_EXPL
            },
            exceptions.StateInvalid: {
                'code': 431,
                'title': 'requestedStateInvalid',
                'explanation': _STATEINVALID_EXPL
            },
            exceptions.PortInUse: {
                'code': 432,
                'title': 'portInUse',
                'explanation': _PORTINUSE_EXPL
            },
            exceptions.AlreadyAttached: {
                'code': 440,
                'title': 'alreadyAttached',
                'explanation': _ALREADYATTACHED_EXPL
            },
            exceptions.NotImplementedError: {
                'code': 501,
                'title': 'notImplemented',
                'explanation': _NOTIMPLEMENTED_EXPL
            }
    }

    def __init__(self, inner_exc):
        _fault_data = self._fault_dict.get(type(inner_exc), None)
        if _fault_data:
            self.code = _fault_data['code']
            self.title = _fault_data['title']
            self.explanation = _fault_data['explanation']
        super(webob.exc.HTTPClientError, self).__init__(inner_exc)


class Quantum11HTTPError(webob.exc.HTTPClientError):

    _fault_dict = {
            exceptions.NetworkNotFound: {
                'code': webob.exc.HTTPNotFound.code,
                'title': webob.exc.HTTPNotFound.title,
                'type': 'NetworkNotFound',
                'explanation': _NETNOTFOUND_EXPL
            },
            exceptions.NetworkInUse: {
                'code': webob.exc.HTTPConflict.code,
                'title': webob.exc.HTTPConflict.title,
                'type': 'NetworkInUse',
                'explanation': _NETINUSE_EXPL
            },
            exceptions.PortNotFound: {
                'code': webob.exc.HTTPNotFound.code,
                'title': webob.exc.HTTPNotFound.title,
                'type': 'PortNotFound',
                'explanation': _PORTNOTFOUND_EXPL
            },
            exceptions.StateInvalid: {
                'code': webob.exc.HTTPBadRequest.code,
                'title': webob.exc.HTTPBadRequest.title,
                'type': 'RequestedStateInvalid',
                'explanation': _STATEINVALID_EXPL
            },
            exceptions.PortInUse: {
                'code': webob.exc.HTTPConflict.code,
                'title': webob.exc.HTTPConflict.title,
                'type': 'PortInUse',
                'explanation': _PORTINUSE_EXPL
            },
            exceptions.AlreadyAttached: {
                'code': webob.exc.HTTPConflict.code,
                'title': webob.exc.HTTPConflict.title,
                'type': 'AlreadyAttached',
                'explanation': _ALREADYATTACHED_EXPL
            }
    }

    def __init__(self, inner_exc):
        _fault_data = self._fault_dict.get(type(inner_exc), None)
        if _fault_data:
            self.code = _fault_data['code']
            self.title = _fault_data['title']
            self.explanation = _fault_data['explanation']
            self.type = _fault_data['type']
        super(webob.exc.HTTPClientError, self).__init__(inner_exc)

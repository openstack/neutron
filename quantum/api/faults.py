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


class QuantumHTTPError(webob.exc.HTTPClientError):

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
            }
    }

    def __init__(self, inner_exc):
        _fault_data = self._fault_dict.get(type(inner_exc), None)
        if _fault_data:
            self.code = _fault_data['code']
            self.title = _fault_data['title']
            self.explanation = _fault_data['explanation']
        super(webob.exc.HTTPClientError, self).__init__(inner_exc)

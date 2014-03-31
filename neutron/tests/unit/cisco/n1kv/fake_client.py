# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 Cisco Systems, Inc.
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
# @author: Abhishek Raut, Cisco Systems Inc.
# @author: Sourabh Patwardhan, Cisco Systems Inc.

from neutron.openstack.common import log as logging
from neutron.plugins.cisco.common import cisco_exceptions
from neutron.plugins.cisco.n1kv.n1kv_client import Client as n1kv_client

LOG = logging.getLogger(__name__)

_resource_metadata = {'port': ['id', 'macAddress', 'ipAddress', 'subnetId'],
                      'vmnetwork': ['name', 'networkSegmentId',
                                    'networkSegment', 'portProfile',
                                    'portProfileId', 'tenantId',
                                    'portId', 'macAddress',
                                    'ipAddress', 'subnetId']}


class TestClient(n1kv_client):

    def __init__(self, **kwargs):
        self.broken = False
        self.inject_params = False
        super(TestClient, self).__init__()

    def _do_request(self, method, action, body=None, headers=None):
        if self.broken:
            raise cisco_exceptions.VSMError(reason='VSM:Internal Server Error')
        if self.inject_params and body:
            body['invalidKey'] = 'catchMeIfYouCan'
        if method == 'POST':
            return _validate_resource(action, body)


class TestClientInvalidRequest(TestClient):

    def __init__(self, **kwargs):
        super(TestClientInvalidRequest, self).__init__()
        self.inject_params = True


def _validate_resource(action, body=None):
    if body:
        body_set = set(body.keys())
    else:
        return
    if 'vm-network' in action and 'port' not in action:
        vmnetwork_set = set(_resource_metadata['vmnetwork'])
        if body_set - vmnetwork_set:
            raise cisco_exceptions.VSMError(reason='Invalid Request')
    elif 'port' in action:
        port_set = set(_resource_metadata['port'])
        if body_set - port_set:
            raise cisco_exceptions.VSMError(reason='Invalid Request')
    else:
        return

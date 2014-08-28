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
from neutron.plugins.cisco.common import cisco_exceptions as c_exc
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
        self.total_profiles = 2
        super(TestClient, self).__init__()

    def _get_total_profiles(self):
        return self.total_profiles

    def _do_request(self, method, action, body=None, headers=None):
        if self.broken:
            raise c_exc.VSMError(reason='VSM:Internal Server Error')
        if self.inject_params and body:
            body['invalidKey'] = 'catchMeIfYouCan'
        if method == 'POST':
            return _validate_resource(action, body)
        elif method == 'GET':
            if 'virtual-port-profile' in action:
                profiles = _policy_profile_generator_xml(
                    self._get_total_profiles())
                return self._deserialize(profiles, 200)
            else:
                raise c_exc.VSMError(reason='VSM:Internal Server Error')


class TestClientInvalidRequest(TestClient):

    def __init__(self, **kwargs):
        super(TestClientInvalidRequest, self).__init__()
        self.inject_params = True


class TestClientInvalidResponse(TestClient):

    def __init__(self, **kwargs):
        super(TestClientInvalidResponse, self).__init__()
        self.broken = True


def _validate_resource(action, body=None):
    if body:
        body_set = set(body.keys())
    else:
        return
    if 'vm-network' in action and 'port' not in action:
        vmnetwork_set = set(_resource_metadata['vmnetwork'])
        if body_set - vmnetwork_set:
            raise c_exc.VSMError(reason='Invalid Request')
    elif 'port' in action:
        port_set = set(_resource_metadata['port'])
        if body_set - port_set:
            raise c_exc.VSMError(reason='Invalid Request')
    else:
        return


def _policy_profile_generator_xml(total_profiles):
    """
    Generate policy profile response in XML format.

    :param total_profiles: integer representing total number of profiles to
                           return
    """
    xml = ["""<?xml version="1.0" encoding="utf-8"?>
           <set name="virtual_port_profile_set">"""]
    template = (
        '<instance name="%(num)d"'
        ' url="/api/n1k/virtual-port-profile/%(num)s">'
        '<properties>'
        '<id>00000000-0000-0000-0000-00000000000%(num)s</id>'
        '<name>pp-%(num)s</name>'
        '</properties>'
        '</instance>'
    )
    xml.extend(template % {'num': n} for n in range(1, total_profiles + 1))
    xml.append("</set>")
    return ''.join(xml)

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack LLC
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

""" Stubs for client tools unit tests """

from quantum import client
from tests.unit import testlib_api


def stubout_send_request(stubs, api):
    """Simulates a failure in fetch image_glance_disk."""

    def fake_send_request(self, conn, method, action, body, headers):
        # ignore headers and connection 
        req = testlib_api.create_request(action, body,
                                         "application/json", method)
        res = req.get_response(api)
        return res
    
    stubs.Set(client.Client, '_send_request', fake_send_request)
    
class FakeHTTPConnection:
    """ stub HTTP connection class for CLI testing """ 
    pass    

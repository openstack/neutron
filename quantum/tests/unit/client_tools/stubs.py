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


from quantum import api as server
from quantum.tests.unit import testlib_api


class FakeStdout:

    def __init__(self):
        self.content = []

    def write(self, text):
        self.content.append(text)

    def make_string(self):
        result = ''
        for line in self.content:
            result = result + line
        return result


class FakeHTTPConnection:
    """ stub HTTP connection class for CLI testing """
    def __init__(self, _1, _2):
        # Ignore host and port parameters
        self._req = None
        plugin = 'quantum.plugins.sample.SamplePlugin.FakePlugin'
        options = dict(plugin_provider=plugin)
        self._api = server.APIRouterV11(options)

    def request(self, method, action, body, headers):
        # TODO: remove version prefix from action!
        parts = action.split('/', 2)
        path = '/' + parts[2]
        self._req = testlib_api.create_request(path, body, "application/json",
                                               method)

    def getresponse(self):
        res = self._req.get_response(self._api)

        def _fake_read():
            """ Trick for making a webob.Response look like a
                httplib.Response

            """
            return res.body

        setattr(res, 'read', _fake_read)
        return res

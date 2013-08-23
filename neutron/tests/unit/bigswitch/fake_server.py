# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Big Switch Networks, Inc.  All rights reserved.
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
# @author: Kevin Benton, <kevin.benton@bigswitch.com>
#


class HTTPResponseMock():
    status = 200
    reason = 'OK'

    def __init__(self, sock, debuglevel=0, strict=0, method=None,
                 buffering=False):
        pass

    def read(self):
        return "{'status': '200 OK'}"


class HTTPResponseMock404(HTTPResponseMock):
    status = 404
    reason = 'Not Found'

    def read(self):
        return "{'status': '404 Not Found'}"


class HTTPResponseMock500(HTTPResponseMock):
    status = 500
    reason = 'Internal Server Error'

    def __init__(self, sock, debuglevel=0, strict=0, method=None,
                 buffering=False, errmsg='500 Internal Server Error'):
        self.errmsg = errmsg

    def read(self):
        return "{'status': '%s'}" % self.errmsg


class HTTPConnectionMock():

    def __init__(self, server, port, timeout):
        self.response = None
        self.broken = False
        # Port 9000 is the broken server
        if port == 9000:
            self.broken = True
            errmsg = "This server is broken, please try another"
            self.response = HTTPResponseMock500(None, errmsg=errmsg)

    def request(self, action, uri, body, headers):
        if self.broken and "ExceptOnBadServer" in uri:
            raise Exception("Broken server got an unexpected request")
        if self.response:
            return

        # detachment may return 404 and plugin shouldn't die
        if uri.endswith('attachment') and action == 'DELETE':
            self.response = HTTPResponseMock404(None)
        else:
            self.response = HTTPResponseMock(None)

        # Port creations/updates must contain binding information
        if ('port' in uri and 'attachment' not in uri
            and 'binding' not in body and action in ('POST', 'PUT')):
            errmsg = "Port binding info missing in port request '%s'" % body
            self.response = HTTPResponseMock500(None, errmsg=errmsg)
            return

        return

    def getresponse(self):
        return self.response

    def close(self):
        pass


class HTTPConnectionMock500(HTTPConnectionMock):

    def __init__(self, server, port, timeout):
        self.response = HTTPResponseMock500(None)
        self.broken = True

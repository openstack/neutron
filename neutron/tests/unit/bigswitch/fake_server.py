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

from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.plugins.bigswitch import servermanager

LOG = logging.getLogger(__name__)


class HTTPResponseMock():
    status = 200
    reason = 'OK'

    def __init__(self, sock, debuglevel=0, strict=0, method=None,
                 buffering=False):
        pass

    def read(self):
        return "{'status': '200 OK'}"

    def getheader(self, header):
        return None


class HTTPResponseMock404(HTTPResponseMock):
    status = 404
    reason = 'Not Found'

    def read(self):
        return "{'status': '%s 404 Not Found'}" % servermanager.NXNETWORK


class HTTPResponseMock500(HTTPResponseMock):
    status = 500
    reason = 'Internal Server Error'

    def __init__(self, sock, debuglevel=0, strict=0, method=None,
                 buffering=False, errmsg='500 Internal Server Error'):
        self.errmsg = errmsg

    def read(self):
        return "{'status': '%s'}" % self.errmsg


class HTTPConnectionMock(object):

    def __init__(self, server, port, timeout):
        self.response = None
        self.broken = False
        # Port 9000 is the broken server
        if port == 9000:
            self.broken = True
            errmsg = "This server is broken, please try another"
            self.response = HTTPResponseMock500(None, errmsg=errmsg)

    def request(self, action, uri, body, headers):
        LOG.debug(_("Request: action=%(action)s, uri=%(uri)r, "
                    "body=%(body)s, headers=%(headers)s"),
                  {'action': action, 'uri': uri,
                   'body': body, 'headers': headers})
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


class HTTPConnectionMock404(HTTPConnectionMock):

    def __init__(self, server, port, timeout):
        self.response = HTTPResponseMock404(None)
        self.broken = True


class HTTPConnectionMock500(HTTPConnectionMock):

    def __init__(self, server, port, timeout):
        self.response = HTTPResponseMock500(None)
        self.broken = True


class VerifyMultiTenantFloatingIP(HTTPConnectionMock):

    def request(self, action, uri, body, headers):
        # Only handle network update requests
        if 'network' in uri and 'tenant' in uri and 'ports' not in uri:
            req = jsonutils.loads(body)
            if 'network' not in req or 'floatingips' not in req['network']:
                msg = _("No floating IPs in request"
                        "uri=%(uri)s, body=%(body)s") % {'uri': uri,
                                                         'body': body}
                raise Exception(msg)
            distinct_tenants = []
            for flip in req['network']['floatingips']:
                if flip['tenant_id'] not in distinct_tenants:
                    distinct_tenants.append(flip['tenant_id'])
            if len(distinct_tenants) < 2:
                msg = _("Expected floating IPs from multiple tenants."
                        "uri=%(uri)s, body=%(body)s") % {'uri': uri,
                                                         'body': body}
                raise Exception(msg)
        super(VerifyMultiTenantFloatingIP,
              self).request(action, uri, body, headers)


class HTTPSMockBase(HTTPConnectionMock):
    expected_cert = ''
    combined_cert = None

    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 strict=None, timeout=None, source_address=None):
        self.host = host
        super(HTTPSMockBase, self).__init__(host, port, timeout)

    def request(self, method, url, body=None, headers={}):
        self.connect()
        super(HTTPSMockBase, self).request(method, url, body, headers)


class HTTPSNoValidation(HTTPSMockBase):

    def connect(self):
        if self.combined_cert:
            raise Exception('combined_cert set on NoValidation')


class HTTPSCAValidation(HTTPSMockBase):
    expected_cert = 'DUMMYCERTIFICATEAUTHORITY'

    def connect(self):
        contents = get_cert_contents(self.combined_cert)
        if self.expected_cert not in contents:
            raise Exception('No dummy CA cert in cert_file')


class HTTPSHostValidation(HTTPSMockBase):
    expected_cert = 'DUMMYCERTFORHOST%s'

    def connect(self):
        contents = get_cert_contents(self.combined_cert)
        expected = self.expected_cert % self.host
        if expected not in contents:
            raise Exception(_('No host cert for %(server)s in cert %(cert)s'),
                            {'server': self.host, 'cert': contents})


def get_cert_contents(path):
    raise Exception('METHOD MUST BE MOCKED FOR TEST')

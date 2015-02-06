# Copyright 2013 VMware, Inc
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

import base64

import eventlet
from oslo_serialization import jsonutils

from neutron.plugins.vmware.vshield.common import exceptions

httplib2 = eventlet.import_patched('httplib2')


def xmldumps(obj):
    config = ""
    if isinstance(obj, dict):
        for key, value in obj.iteritems():
            cfg = "<%s>%s</%s>" % (key, xmldumps(value), key)
            config += cfg
    elif isinstance(obj, list):
        for value in obj:
            config += xmldumps(value)
    else:
        config = obj

    return config


class VcnsApiHelper(object):
    errors = {
        303: exceptions.ResourceRedirect,
        400: exceptions.RequestBad,
        403: exceptions.Forbidden,
        404: exceptions.ResourceNotFound,
        415: exceptions.MediaTypeUnsupport,
        503: exceptions.ServiceUnavailable
    }

    def __init__(self, address, user, password, format='json'):
        self.authToken = base64.encodestring("%s:%s" % (user, password))
        self.user = user
        self.passwd = password
        self.address = address
        self.format = format
        if format == 'json':
            self.encode = jsonutils.dumps
        else:
            self.encode = xmldumps

    def request(self, method, uri, params=None):
        uri = self.address + uri
        http = httplib2.Http()
        http.disable_ssl_certificate_validation = True
        headers = {
            'Content-Type': 'application/' + self.format,
            'Accept': 'application/' + 'json',
            'Authorization': 'Basic ' + self.authToken
        }
        body = self.encode(params) if params else None
        header, response = http.request(uri, method,
                                        body=body, headers=headers)
        status = int(header['status'])
        if 200 <= status < 300:
            return header, response
        if status in self.errors:
            cls = self.errors[status]
        else:
            cls = exceptions.VcnsApiException
        raise cls(uri=uri, status=status, header=header, response=response)

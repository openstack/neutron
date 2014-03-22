# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 NEC Corporation.  All rights reserved.
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
# @author: Ryota MIBU

import httplib
import json
import socket
import time

from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.nec.common import config
from neutron.plugins.nec.common import exceptions as nexc


LOG = logging.getLogger(__name__)


class OFCClient(object):
    """A HTTP/HTTPS client for OFC Drivers."""

    def __init__(self, host="127.0.0.1", port=8888, use_ssl=False,
                 key_file=None, cert_file=None):
        """Creates a new client to some OFC.

        :param host: The host where service resides
        :param port: The port where service resides
        :param use_ssl: True to use SSL, False to use HTTP
        :param key_file: The SSL key file to use if use_ssl is true
        :param cert_file: The SSL cert file to use if use_ssl is true
        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.key_file = key_file
        self.cert_file = cert_file
        self.connection = None

    def get_connection(self):
        """Returns the proper connection."""
        if self.use_ssl:
            connection_type = httplib.HTTPSConnection
        else:
            connection_type = httplib.HTTPConnection

        # Open connection and send request, handling SSL certs
        certs = {'key_file': self.key_file, 'cert_file': self.cert_file}
        certs = dict((x, certs[x]) for x in certs if certs[x] is not None)
        if self.use_ssl and len(certs):
            conn = connection_type(self.host, self.port, **certs)
        else:
            conn = connection_type(self.host, self.port)
        return conn

    def _format_error_message(self, status, detail):
        detail = ' ' + detail if detail else ''
        return (_("Operation on OFC failed: %(status)s%(msg)s") %
                {'status': status, 'msg': detail})

    def do_single_request(self, method, action, body=None):
        action = config.OFC.path_prefix + action
        LOG.debug(_("Client request: %(host)s:%(port)s "
                    "%(method)s %(action)s [%(body)s]"),
                  {'host': self.host, 'port': self.port,
                   'method': method, 'action': action, 'body': body})
        if type(body) is dict:
            body = json.dumps(body)
        try:
            conn = self.get_connection()
            headers = {"Content-Type": "application/json"}
            conn.request(method, action, body, headers)
            res = conn.getresponse()
            data = res.read()
            LOG.debug(_("OFC returns [%(status)s:%(data)s]"),
                      {'status': res.status,
                       'data': data})

            # Try to decode JSON data if possible.
            try:
                data = json.loads(data)
            except (ValueError, TypeError):
                pass

            if res.status in (httplib.OK,
                              httplib.CREATED,
                              httplib.ACCEPTED,
                              httplib.NO_CONTENT):
                return data
            elif res.status == httplib.SERVICE_UNAVAILABLE:
                retry_after = res.getheader('retry-after')
                LOG.warning(_("OFC returns ServiceUnavailable "
                              "(retry-after=%s)"), retry_after)
                raise nexc.OFCServiceUnavailable(retry_after=retry_after)
            elif res.status == httplib.NOT_FOUND:
                LOG.info(_("Specified resource %s does not exist on OFC "),
                         action)
                raise nexc.OFCResourceNotFound(resource=action)
            else:
                LOG.warning(_("Operation on OFC failed: "
                              "status=%(status)s, detail=%(detail)s"),
                            {'status': res.status, 'detail': data})
                params = {'reason': _("Operation on OFC failed"),
                          'status': res.status}
                if isinstance(data, dict):
                    params['err_code'] = data.get('err_code')
                    params['err_msg'] = data.get('err_msg')
                else:
                    params['err_msg'] = data
                raise nexc.OFCException(**params)
        except (socket.error, IOError) as e:
            reason = _("Failed to connect OFC : %s") % e
            LOG.error(reason)
            raise nexc.OFCException(reason=reason)

    def do_request(self, method, action, body=None):
        max_attempts = config.OFC.api_max_attempts
        for i in range(max_attempts, 0, -1):
            try:
                return self.do_single_request(method, action, body)
            except nexc.OFCServiceUnavailable as e:
                with excutils.save_and_reraise_exception() as ctxt:
                    try:
                        wait_time = int(e.retry_after)
                    except (ValueError, TypeError):
                        wait_time = None
                    if i > 1 and wait_time:
                        LOG.info(_("Waiting for %s seconds due to "
                                   "OFC Service_Unavailable."), wait_time)
                        time.sleep(wait_time)
                        ctxt.reraise = False
                        continue

    def get(self, action):
        return self.do_request("GET", action)

    def post(self, action, body=None):
        return self.do_request("POST", action, body=body)

    def put(self, action, body=None):
        return self.do_request("PUT", action, body=body)

    def delete(self, action):
        return self.do_request("DELETE", action)

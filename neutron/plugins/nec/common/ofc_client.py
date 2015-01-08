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

import time

from oslo_serialization import jsonutils
from oslo_utils import excutils
import requests

from neutron.i18n import _LI, _LW
from neutron.openstack.common import log as logging
from neutron.plugins.nec.common import config
from neutron.plugins.nec.common import exceptions as nexc


LOG = logging.getLogger(__name__)


class OFCClient(object):
    """A HTTP/HTTPS client for OFC Drivers."""

    def __init__(self, host="127.0.0.1", port=8888, use_ssl=False,
                 key_file=None, cert_file=None, insecure_ssl=False):
        """Creates a new client to some OFC.

        :param host: The host where service resides
        :param port: The port where service resides
        :param use_ssl: True to use SSL, False to use HTTP
        :param key_file: The SSL key file to use if use_ssl is true
        :param cert_file: The SSL cert file to use if use_ssl is true
        :param insecure_ssl: Don't verify SSL certificate
        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.key_file = key_file
        self.cert_file = cert_file
        self.insecure_ssl = insecure_ssl
        self.connection = None

    def _format_error_message(self, status, detail):
        detail = ' ' + detail if detail else ''
        return (_("Operation on OFC failed: %(status)s%(msg)s") %
                {'status': status, 'msg': detail})

    def _get_response(self, method, action, body=None):
            headers = {"Content-Type": "application/json"}
            protocol = "http"
            certs = {'key_file': self.key_file, 'cert_file': self.cert_file}
            certs = dict((x, certs[x]) for x in certs if certs[x] is not None)
            verify = True

            if self.use_ssl:
                protocol = "https"
                if self.insecure_ssl:
                    verify = False

            url = "%s://%s:%d%s" % (protocol, self.host, int(self.port),
                                    action)

            res = requests.request(method, url, data=body, headers=headers,
                                   cert=certs, verify=verify)
            return res

    def do_single_request(self, method, action, body=None):
        action = config.OFC.path_prefix + action
        LOG.debug("Client request: %(host)s:%(port)s "
                  "%(method)s %(action)s [%(body)s]",
                  {'host': self.host, 'port': self.port,
                   'method': method, 'action': action, 'body': body})
        if type(body) is dict:
            body = jsonutils.dumps(body)
        try:
            res = self._get_response(method, action, body)
            data = res.text
            LOG.debug("OFC returns [%(status)s:%(data)s]",
                      {'status': res.status_code,
                       'data': data})

            # Try to decode JSON data if possible.
            try:
                data = jsonutils.loads(data)
            except (ValueError, TypeError):
                pass

            if res.status_code in (requests.codes.OK,
                                   requests.codes.CREATED,
                                   requests.codes.ACCEPTED,
                                   requests.codes.NO_CONTENT):
                return data
            elif res.status_code == requests.codes.SERVICE_UNAVAILABLE:
                retry_after = res.headers.get('retry-after')
                LOG.warning(_LW("OFC returns ServiceUnavailable "
                                "(retry-after=%s)"), retry_after)
                raise nexc.OFCServiceUnavailable(retry_after=retry_after)
            elif res.status_code == requests.codes.NOT_FOUND:
                LOG.info(_LI("Specified resource %s does not exist on OFC "),
                         action)
                raise nexc.OFCResourceNotFound(resource=action)
            else:
                LOG.warning(_LW("Operation on OFC failed: "
                                "status=%(status)s, detail=%(detail)s"),
                            {'status': res.status_code, 'detail': data})
                params = {'reason': _("Operation on OFC failed"),
                          'status': res.status_code}
                if isinstance(data, dict):
                    params['err_code'] = data.get('err_code')
                    params['err_msg'] = data.get('err_msg')
                else:
                    params['err_msg'] = data
                raise nexc.OFCException(**params)
        except requests.exceptions.RequestException as e:
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
                        LOG.info(_LI("Waiting for %s seconds due to "
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

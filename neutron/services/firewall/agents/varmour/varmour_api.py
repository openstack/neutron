# Copyright 2013 vArmour Networks Inc.
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

import base64

import httplib2
from oslo.config import cfg

from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.services.firewall.agents.varmour import varmour_utils as va_utils

OPTS = [
    cfg.StrOpt('director', default='localhost',
               help=_("vArmour director ip")),
    cfg.StrOpt('director_port', default='443',
               help=_("vArmour director port")),
    cfg.StrOpt('username', default='varmour',
               help=_("vArmour director username")),
    cfg.StrOpt('password', default='varmour', secret=True,
               help=_("vArmour director password")), ]

cfg.CONF.register_opts(OPTS, "vArmour")

LOG = logging.getLogger(__name__)

REST_URL_PREFIX = '/api/v1.0'


class vArmourAPIException(Exception):
    message = _("An unknown exception.")

    def __init__(self, **kwargs):
        try:
            self.err = self.message % kwargs

        except Exception:
            self.err = self.message

    def __str__(self):
        return self.err


class AuthenticationFailure(vArmourAPIException):
    message = _("Invalid login credential.")


class vArmourRestAPI(object):

    def __init__(self):
        LOG.debug(_('vArmourRestAPI: started'))
        self.user = cfg.CONF.vArmour.username
        self.passwd = cfg.CONF.vArmour.password
        self.server = cfg.CONF.vArmour.director
        self.port = cfg.CONF.vArmour.director_port
        self.timeout = 3
        self.key = ''

    def auth(self):
        headers = {}
        enc = base64.b64encode(self.user + ':' + self.passwd)
        headers['Authorization'] = 'Basic ' + enc
        resp = self.rest_api('POST', va_utils.REST_URL_AUTH, None, headers)
        if resp and resp['status'] == 200:
            self.key = resp['body']['auth']
            return True
        else:
            raise AuthenticationFailure()

    def commit(self):
        self.rest_api('POST', va_utils.REST_URL_COMMIT)

    def rest_api(self, method, url, body=None, headers=None):
        url = REST_URL_PREFIX + url
        if body:
            body_data = jsonutils.dumps(body)
        else:
            body_data = ''
        if not headers:
            headers = {}
            enc = base64.b64encode('%s:%s' % (self.user, self.key))
            headers['Authorization'] = 'Basic ' + enc

        LOG.debug(_("vArmourRestAPI: %(server)s %(port)s"),
                  {'server': self.server, 'port': self.port})

        try:
            action = "https://" + self.server + ":" + self.port + url

            LOG.debug(_("vArmourRestAPI Sending: "
                        "%(method)s %(action)s %(headers)s %(body_data)s"),
                      {'method': method, 'action': action,
                       'headers': headers, 'body_data': body_data})

            h = httplib2.Http(timeout=3,
                              disable_ssl_certificate_validation=True)
            resp, resp_str = h.request(action, method,
                                       body=body_data,
                                       headers=headers)

            LOG.debug(_("vArmourRestAPI Response: %(status)s %(resp_str)s"),
                      {'status': resp.status, 'resp_str': resp_str})

            if resp.status == 200:
                return {'status': resp.status,
                        'reason': resp.reason,
                        'body': jsonutils.loads(resp_str)}
        except Exception:
            LOG.error(_('vArmourRestAPI: Could not establish HTTP connection'))

    def del_cfg_objs(self, url, prefix):
        resp = self.rest_api('GET', url)
        if resp and resp['status'] == 200:
            olist = resp['body']['response']
            if not olist:
                return

            for o in olist:
                if o.startswith(prefix):
                    self.rest_api('DELETE', url + '/"name:%s"' % o)
            self.commit()

    def count_cfg_objs(self, url, prefix):
        count = 0
        resp = self.rest_api('GET', url)
        if resp and resp['status'] == 200:
            for o in resp['body']['response']:
                if o.startswith(prefix):
                    count += 1

        return count

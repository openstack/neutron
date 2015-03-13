# Copyright 2014 OneConvergence, Inc. All Rights Reserved.
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

"""Library to talk to NVSD controller."""

import httplib
import time

from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
import requests
from six.moves.urllib import parse

from neutron.i18n import _LE, _LW
import neutron.plugins.oneconvergence.lib.exception as exception

LOG = logging.getLogger(__name__)


def initialize_plugin_helper():
    nvsdcontroller = NVSDController()
    return nvsdcontroller


class NVSDController(object):

    """Encapsulates the NVSD Controller details."""

    def __init__(self):

        self._host = cfg.CONF.nvsd.nvsd_ip
        self._port = cfg.CONF.nvsd.nvsd_port
        self._user = cfg.CONF.nvsd.nvsd_user
        self._password = cfg.CONF.nvsd.nvsd_passwd
        self._retries = cfg.CONF.nvsd.nvsd_retries
        self._request_timeout = float(cfg.CONF.nvsd.request_timeout)
        self.api_url = 'http://' + self._host + ':' + str(self._port)

        self.pool = requests.Session()

        self.auth_token = None

    def do_request(self, method, url=None, headers=None, data=None):
        response = self.pool.request(method, url=url,
                                     headers=headers, data=data,
                                     timeout=self._request_timeout)
        return response

    def login(self):
        """Login to NVSD Controller."""

        headers = {"Content-Type": "application/json"}

        login_url = parse.urljoin(self.api_url,
                                  "/pluginhandler/ocplugin/authmgmt/login")

        data = jsonutils.dumps({"user_name": self._user,
                                "passwd": self._password})

        attempts = 0

        while True:
            if attempts < self._retries:
                attempts += 1
            elif self._retries == 0:
                attempts = 0
            else:
                msg = _("Unable to connect to NVSD controller. Exiting after "
                        "%(retries)s attempts") % {'retries': self._retries}
                LOG.error(msg)
                raise exception.ServerException(reason=msg)
            try:
                response = self.do_request("POST", url=login_url,
                                           headers=headers, data=data)
                break
            except Exception as e:
                LOG.error(_LE("Login Failed: %s"), e)
                LOG.error(_LE("Unable to establish connection"
                              " with Controller %s"), self.api_url)
                LOG.error(_LE("Retrying after 1 second..."))
                time.sleep(1)

        if response.status_code == requests.codes.ok:
            LOG.debug("Login Successful %(uri)s "
                      "%(status)s", {'uri': self.api_url,
                                     'status': response.status_code})
            self.auth_token = jsonutils.loads(response.content)["session_uuid"]
            LOG.debug("AuthToken = %s", self.auth_token)
        else:
            LOG.error(_LE("login failed"))

        return

    def request(self, method, url, body="", content_type="application/json"):
        """Issue a request to NVSD controller."""

        if self.auth_token is None:
            LOG.warning(_LW("No Token, Re-login"))
            self.login()

        headers = {"Content-Type": content_type}

        uri = parse.urljoin(url, "?authToken=%s" % self.auth_token)

        url = parse.urljoin(self.api_url, uri)

        request_ok = False
        response = None

        try:
            response = self.do_request(method, url=url,
                                       headers=headers, data=body)

            LOG.debug("request: %(method)s %(uri)s successful",
                      {'method': method, 'uri': self.api_url + uri})
            request_ok = True
        except httplib.IncompleteRead as e:
            response = e.partial
            request_ok = True
        except Exception as e:
            LOG.error(_LE("request: Request failed from "
                        "Controller side :%s"), e)

        if response is None:
            # Timeout.
            LOG.error(_LE("Response is Null, Request timed out: %(method)s to "
                          "%(uri)s"), {'method': method, 'uri': uri})
            self.auth_token = None
            raise exception.RequestTimeout()

        status = response.status_code
        if status == requests.codes.unauthorized:
            self.auth_token = None
            # Raise an exception to inform that the request failed.
            raise exception.UnAuthorizedException()

        if status in self.error_codes:
            LOG.error(_LE("Request %(method)s %(uri)s body = %(body)s failed "
                          "with status %(status)s. Reason: %(reason)s)"),
                      {'method': method,
                       'uri': uri, 'body': body,
                       'status': status,
                       'reason': response.reason})
            raise self.error_codes[status]()
        elif status not in (requests.codes.ok, requests.codes.created,
                            requests.codes.no_content):
            LOG.error(_LE("%(method)s to %(url)s, unexpected response code: "
                          "%(status)d"), {'method': method, 'url': url,
                                          'status': status})
            return

        if not request_ok:
            LOG.error(_LE("Request failed from Controller side with "
                        "Status=%s"), status)
            raise exception.ServerException()
        else:
            LOG.debug("Success: %(method)s %(url)s status=%(status)s",
                      {'method': method, 'url': self.api_url + uri,
                       'status': status})
        response.body = response.content
        return response

    error_codes = {
        404: exception.NotFoundException,
        409: exception.BadRequestException,
        500: exception.InternalServerError,
        503: exception.ServerException,
        403: exception.ForbiddenException,
        301: exception.NVSDAPIException,
        307: exception.NVSDAPIException,
        400: exception.NVSDAPIException,
    }

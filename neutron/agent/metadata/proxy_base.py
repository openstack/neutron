# Copyright 2012 New Dream Network, LLC (DreamHost)
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

import abc
import urllib

import netaddr
from neutron_lib import constants
from oslo_log import log as logging
from oslo_utils import netutils
import requests
import webob

from neutron._i18n import _
from neutron.agent.linux import utils as agent_utils
from neutron.common import ipv6_utils
from neutron.common import utils as common_utils
from neutron.conf.agent.metadata import config

LOG = logging.getLogger(__name__)

MODE_MAP = {
    config.USER_MODE: 0o644,
    config.GROUP_MODE: 0o664,
    config.ALL_MODE: 0o666,
}


class MetadataProxyHandlerBase(metaclass=abc.ABCMeta):
    NETWORK_ID_HEADER: str
    ROUTER_ID_HEADER: str

    def __init__(self, conf, has_cache=False, **kwargs):
        self.conf = conf
        self._has_cache = has_cache
        super().__init__(**kwargs)

    @abc.abstractmethod
    def get_port(self, remote_address, network_id=None, remote_mac=None,
                 router_id=None, skip_cache=False):
        """Search for a single port that contain the given IP address and
        belongs to the given network.

        If no network is passed, ports are searched on all networks connected
        to a given router. Either one of network_id or router_id must be given.

        :param remote_address: IP address to search for
        :param network_id: Network ID to filter by, if given
        :param remote_mac: Remote MAC to filter by, if given
        :param router_id: Router ID to filter by, if given
        :param skip_cache: When to skip getting entry from cache

        """
        pass

    @webob.dec.wsgify(RequestClass=webob.Request)
    def __call__(self, req):
        try:
            LOG.debug("Request: %s", req)

            instance_id, project_id = self._get_instance_and_project_id(req)
            if instance_id:
                res = self._proxy_request(instance_id, project_id, req)
                if isinstance(res, webob.exc.HTTPNotFound) and self._has_cache:
                    LOG.info("The instance: %s is not present anymore, "
                             "skipping cache...", instance_id)
                    instance_id, project_id = (
                        self._get_instance_and_project_id(req,
                                                          skip_cache=True))
                    if instance_id:
                        res = self._proxy_request(instance_id, project_id, req)
                return res
            return webob.exc.HTTPNotFound()

        except Exception:
            LOG.exception("Unexpected error.")
            msg = _('An unknown error has occurred. '
                    'Please try your request again.')
            explanation = str(msg)
            return webob.exc.HTTPInternalServerError(explanation=explanation)

    def _get_instance_id(self, req):
        """Returns the network ID and the router ID from the request"""
        network_id = req.headers.get(self.NETWORK_ID_HEADER)
        router_id = (req.headers.get(self.ROUTER_ID_HEADER)
                     if self.ROUTER_ID_HEADER else None)
        return network_id, router_id

    def _get_instance_and_project_id(self, req, skip_cache=False):
        forwarded_for = req.headers.get('X-Forwarded-For')
        network_id, router_id = self._get_instance_id(req)

        # Only one should be given, drop since it could be spoofed
        if network_id and router_id:
            LOG.debug("Both network and router IDs were specified in proxy "
                      "request, but only a single one of the two is allowed, "
                      "dropping")
            return None, None

        remote_mac = None
        remote_ip = netaddr.IPAddress(forwarded_for)
        if remote_ip.version == constants.IP_VERSION_6:
            if remote_ip.is_ipv4_mapped():
                # When haproxy listens on v4 AND v6 then it inserts ipv4
                # addresses as ipv4-mapped v6 addresses into X-Forwarded-For.
                forwarded_for = str(remote_ip.ipv4())
            if remote_ip.is_link_local():
                # When haproxy sees an ipv6 link-local client address
                # (and sends that to us in X-Forwarded-For) we must rely
                # on the EUI encoded in it, because that's all we can
                # recognize.
                remote_mac = str(netutils.get_mac_addr_by_ipv6(remote_ip))

        instance_id, project_id = self.get_port(forwarded_for,
                                                network_id=network_id,
                                                remote_mac=remote_mac,
                                                router_id=router_id,
                                                skip_cache=skip_cache)
        return instance_id, project_id

    def _proxy_request(self, instance_id, project_id, req):
        headers = {
            'X-Forwarded-For': req.headers.get('X-Forwarded-For'),
            'X-Instance-ID': instance_id,
            'X-Tenant-ID': project_id,
            'X-Instance-ID-Signature': common_utils.sign_instance_id(
                self.conf, instance_id)
        }

        nova_host_port = ipv6_utils.valid_ipv6_url(
            self.conf.nova_metadata_host,
            self.conf.nova_metadata_port)

        url = urllib.parse.urlunsplit((
            self.conf.nova_metadata_protocol,
            nova_host_port,
            req.path_info,
            req.query_string,
            ''))

        disable_ssl_certificate_validation = self.conf.nova_metadata_insecure
        if self.conf.auth_ca_cert and not disable_ssl_certificate_validation:
            verify_cert = self.conf.auth_ca_cert
        else:
            verify_cert = not disable_ssl_certificate_validation

        client_cert = None
        if self.conf.nova_client_cert and self.conf.nova_client_priv_key:
            client_cert = (self.conf.nova_client_cert,
                           self.conf.nova_client_priv_key)

        try:
            resp = requests.request(method=req.method, url=url,
                                    headers=headers,
                                    data=req.body,
                                    cert=client_cert,
                                    verify=verify_cert,
                                    timeout=60)
        except requests.ConnectionError:
            msg = _('The remote metadata server is temporarily unavailable. '
                    'Please try again later.')
            explanation = str(msg)
            return webob.exc.HTTPServiceUnavailable(explanation=explanation)

        if resp.status_code == 200:
            req.response.content_type = resp.headers['content-type']
            req.response.body = resp.content
            LOG.debug(str(resp))
            return req.response
        if resp.status_code == 403:
            LOG.warning(
                'The remote metadata server responded with Forbidden. This '
                'response usually occurs when shared secrets do not match.'
            )
            return webob.exc.HTTPForbidden()
        if resp.status_code == 500:
            msg = _(
                'Remote metadata server experienced an internal server error.'
            )
            LOG.warning(msg)
            explanation = str(msg)
            return webob.exc.HTTPInternalServerError(explanation=explanation)
        if resp.status_code in (400, 404, 409, 502, 503, 504):
            webob_exc_cls = webob.exc.status_map.get(resp.status_code)
            return webob_exc_cls()
        raise Exception(_('Unexpected response code: %s') % resp.status_code)


class UnixDomainMetadataProxyBase(metaclass=abc.ABCMeta):

    def __init__(self, conf):
        self.conf = conf

    def _get_socket_mode(self):
        mode = self.conf.metadata_proxy_socket_mode
        if mode == config.DEDUCE_MODE:
            user = self.conf.metadata_proxy_user
            if (not user or user == '0' or user == 'root' or
                    agent_utils.is_effective_user(user)):
                # user is agent effective user or root => USER_MODE
                mode = config.USER_MODE
            else:
                group = self.conf.metadata_proxy_group
                if not group or agent_utils.is_effective_group(group):
                    # group is agent effective group => GROUP_MODE
                    mode = config.GROUP_MODE
                else:
                    # otherwise => ALL_MODE
                    mode = config.ALL_MODE
        return MODE_MAP[mode]

    @abc.abstractmethod
    def run(self):
        pass

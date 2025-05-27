# Copyright 2012 New Dream Network, LLC (DreamHost)
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

import urllib

import netaddr

from neutron_lib.agent import topics
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.utils import host
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall
from oslo_utils import netutils
import requests
import webob

from neutron._i18n import _
from neutron.agent.common import base_agent_rpc
from neutron.agent.linux import utils as agent_utils
from neutron.agent import rpc as agent_rpc
from neutron.common import cache_utils as cache
from neutron.common import ipv6_utils
from neutron.common import utils as common_utils
from neutron.conf.agent.metadata import config

LOG = logging.getLogger(__name__)

MODE_MAP = {
    config.USER_MODE: 0o644,
    config.GROUP_MODE: 0o664,
    config.ALL_MODE: 0o666,
}


class MetadataPluginAPI(base_agent_rpc.BasePluginApi):
    """Agent-side RPC for metadata agent-to-plugin interaction.

    This class implements the client side of an rpc interface used by the
    metadata service to make calls back into the Neutron plugin.  The server
    side is defined in
    neutron.api.rpc.handlers.metadata_rpc.MetadataRpcCallback.  For more
    information about changing rpc interfaces, see
    doc/source/contributor/internals/rpc_api.rst.

    API version history:
        1.0 - Initial version.
    """

    def __init__(self, topic):
        super().__init__(
            topic=topic,
            namespace=constants.RPC_NAMESPACE_METADATA,
            version='1.0')


class MetadataProxyHandler(object):

    def __init__(self, conf):
        self.conf = conf
        self._cache = cache.get_cache(self.conf)

        self.plugin_rpc = MetadataPluginAPI(topics.PLUGIN)
        self.context = context.get_admin_context_without_session()

    @webob.dec.wsgify(RequestClass=webob.Request)
    def __call__(self, req):
        try:
            LOG.debug("Request: %s", req)

            instance_id, tenant_id = self._get_instance_and_tenant_id(req)
            if instance_id:
                res = self._proxy_request(instance_id, tenant_id, req)
                if isinstance(res, webob.exc.HTTPNotFound):
                    LOG.info("The instance: %s is not present anymore, "
                             "skipping cache...", instance_id)
                    instance_id, tenant_id = self._get_instance_and_tenant_id(
                        req, skip_cache=True)
                    if instance_id:
                        return self._proxy_request(instance_id, tenant_id, req)
                return res
            else:
                return webob.exc.HTTPNotFound()

        except Exception:
            LOG.exception("Unexpected error.")
            msg = _('An unknown error has occurred. '
                    'Please try your request again.')
            explanation = str(msg)
            return webob.exc.HTTPInternalServerError(explanation=explanation)

    def _get_ports_from_server(self, router_id=None, ip_address=None,
                               networks=None, mac_address=None):
        """Get ports from server."""
        filters = self._get_port_filters(
            router_id, ip_address, networks, mac_address)
        return self.plugin_rpc.get_ports(self.context, filters)

    def _get_port_filters(self, router_id=None, ip_address=None,
                          networks=None, mac_address=None):
        filters = {}
        if router_id:
            filters['device_id'] = [router_id]
            filters['device_owner'] = constants.ROUTER_INTERFACE_OWNERS
        # We either get an IP assigned (and therefore known) by neutron
        # via X-Forwarded-For or that header contained a link-local
        # IPv6 address of which neutron only knows the MAC address encoded
        # in it. In the latter case the IPv6 address in X-Forwarded-For
        # is not a fixed ip of the port.
        if mac_address:
            filters['mac_address'] = [mac_address]
        elif ip_address:
            filters['fixed_ips'] = {'ip_address': [ip_address]}
        if networks:
            filters['network_id'] = networks

        return filters

    @cache.cache_method_results
    def _get_router_networks(self, router_id, skip_cache=False):
        """Find all networks connected to given router."""
        internal_ports = self._get_ports_from_server(router_id=router_id)
        return tuple(p['network_id'] for p in internal_ports)

    @cache.cache_method_results
    def _get_ports_for_remote_address(self, remote_address, networks,
                                      skip_cache=False,
                                      remote_mac=None):
        """Get list of ports that has given ip address and are part of
        given networks.

        :param networks: list of networks in which the ip address will be
                         searched for
        :param skip_cache: when have to skip getting entry from cache

        """
        return self._get_ports_from_server(networks=networks,
                                           ip_address=remote_address,
                                           mac_address=remote_mac)

    def _get_ports(self, remote_address, network_id=None, router_id=None,
                   skip_cache=False, remote_mac=None):
        """Search for all ports that contain passed ip address and belongs to
        given network.

        If no network is passed ports are searched on all networks connected to
        given router. Either one of network_id or router_id must be passed.

        :param skip_cache: when have to skip getting entry from cache

        """
        if network_id:
            networks = (network_id,)
        elif router_id:
            networks = self._get_router_networks(router_id,
                                                 skip_cache=skip_cache)
        else:
            raise TypeError(_("Either one of parameter network_id or router_id"
                              " must be passed to _get_ports method."))

        return self._get_ports_for_remote_address(remote_address, networks,
                                                  skip_cache=skip_cache,
                                                  remote_mac=remote_mac)

    def _get_instance_and_tenant_id(self, req, skip_cache=False):
        forwarded_for = req.headers.get('X-Forwarded-For')
        network_id = req.headers.get('X-Neutron-Network-ID')
        router_id = req.headers.get('X-Neutron-Router-ID')

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

        ports = self._get_ports(
            forwarded_for, network_id, router_id,
            skip_cache=skip_cache, remote_mac=remote_mac)
        LOG.debug("Gotten ports for remote_address %(remote_address)s, "
                  "network_id %(network_id)s, router_id %(router_id)s are: "
                  "%(ports)s",
                  {"remote_address": forwarded_for,
                   "network_id": network_id,
                   "router_id": router_id,
                   "ports": ports})

        if len(ports) == 1:
            return ports[0]['device_id'], ports[0]['tenant_id']
        return None, None

    def _proxy_request(self, instance_id, tenant_id, req):
        headers = {
            'X-Forwarded-For': req.headers.get('X-Forwarded-For'),
            'X-Instance-ID': instance_id,
            'X-Tenant-ID': tenant_id,
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

        # Log the proxied request + result in a parsable way
        LOG.info('Metadata request - method: %(method)s path: "%(path)s" '
                 'status: %(status)s client-ip: %(client_ip)s '
                 'project-id: %(project_id)s os-network-id: %(os_network_id)s '
                 'os-router-id: %(os_router_id)s '
                 'os-instance-id: %(os_instance_id)s '
                 'req-duration: %(req_duration)s '
                 'user-agent: "%(user_agent)s"',
            {
                'method': req.method,
                'path': req.url[len(req.host_url):],
                'status': resp.status_code,
                'client_ip': headers['X-Forwarded-For'],
                'project_id': tenant_id,
                'os_network_id': req.headers.get('X-Neutron-Network-ID'),
                'os_router_id': req.headers.get('X-Neutron-Router-ID'),
                'os_instance_id': instance_id,
                'req_duration': resp.elapsed.total_seconds(),
                'user_agent': req.headers.get('User-Agent'),
            })

        if resp.status_code == 200:
            req.response.content_type = resp.headers.get('content-type')
            req.response.body = resp.content
            LOG.debug(str(resp))
            return req.response
        elif resp.status_code == 403:
            LOG.warning(
                'The remote metadata server responded with Forbidden. This '
                'response usually occurs when shared secrets do not match.'
            )
            return webob.exc.HTTPForbidden()
        elif resp.status_code == 500:
            msg = _(
                'Remote metadata server experienced an internal server error.'
            )
            LOG.warning(msg)
            explanation = str(msg)
            return webob.exc.HTTPInternalServerError(explanation=explanation)
        elif resp.status_code in (400, 404, 409, 502, 503, 504):
            webob_exc_cls = webob.exc.status_map.get(resp.status_code)
            return webob_exc_cls()
        else:
            raise Exception(_('Unexpected response code: %s') %
                            resp.status_code)


class UnixDomainMetadataProxy(object):

    def __init__(self, conf):
        self.conf = conf
        agent_utils.ensure_directory_exists_without_file(
            cfg.CONF.metadata_proxy_socket)

    def _init_state_reporting(self):
        self.context = context.get_admin_context_without_session()
        self.failed_state_report = False
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
        self.agent_state = {
            'binary': constants.AGENT_PROCESS_METADATA,
            'host': cfg.CONF.host,
            'topic': 'N/A',
            'configurations': {
                'metadata_proxy_socket': cfg.CONF.metadata_proxy_socket,
                'nova_metadata_host': cfg.CONF.nova_metadata_host,
                'nova_metadata_port': cfg.CONF.nova_metadata_port,
                'log_agent_heartbeats': cfg.CONF.AGENT.log_agent_heartbeats,
            },
            'start_flag': True,
            'agent_type': constants.AGENT_TYPE_METADATA}
        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            self.heartbeat.start(interval=report_interval)

    def _report_state(self):
        try:
            self.state_rpc.report_state(
                self.context,
                self.agent_state,
                use_call=self.agent_state.get('start_flag'))
        except AttributeError:
            # This means the server does not support report_state
            LOG.warning('Neutron server does not support state report.'
                        ' State report for this agent will be disabled.')
            self.heartbeat.stop()
            return
        except Exception:
            self.failed_state_report = True
            LOG.exception("Failed reporting state!")
            return
        if self.failed_state_report:
            self.failed_state_report = False
            LOG.info('Successfully reported state after a previous failure.')
        self.agent_state.pop('start_flag', None)

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

    def run(self):
        server = agent_utils.UnixDomainWSGIServer(
            constants.AGENT_PROCESS_METADATA)
        # Set the default metadata_workers if not yet set in the config file
        md_workers = self.conf.metadata_workers
        if md_workers is None:
            md_workers = host.cpu_count() // 2
        server.start(MetadataProxyHandler(self.conf),
                     self.conf.metadata_proxy_socket,
                     workers=md_workers,
                     backlog=self.conf.metadata_backlog,
                     mode=self._get_socket_mode())
        self._init_state_reporting()
        server.wait()

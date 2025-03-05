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

import io
import socketserver
import urllib

import jinja2
from neutron_lib.agent import topics
from neutron_lib import constants
from neutron_lib import context
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall
from oslo_utils import encodeutils
import requests
import webob
from webob import exc as webob_exc

from neutron._i18n import _
from neutron.agent.common import base_agent_rpc
from neutron.agent.linux import utils as agent_utils
from neutron.agent.metadata import proxy_base
from neutron.agent import rpc as agent_rpc
from neutron.common import ipv6_utils
from neutron.common import utils as common_utils


LOG = logging.getLogger(__name__)

RESPONSE = jinja2.Template("""HTTP/1.1 {{ http_code }}
Content-Type: text/plain; charset=UTF-8
Connection: close
Content-Length: {{ len }}

<html>
 <head>
  <title>{{ title }}</title>
 </head>
 <body>
  <h1>{{ body_title }}</h1>
  {{ body }}<br /><br />


 </body>
</html>""")
RESPONSE_LENGHT = 40


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


class MetadataProxyHandlerBaseSocketServer(
        proxy_base.MetadataProxyHandlerBase):
    @staticmethod
    def _http_response(http_response, request):
        _res = webob.Response(
            body=http_response.content,
            status=http_response.status_code,
            content_type=http_response.headers['content-type'],
            charset=http_response.encoding)
        # NOTE(ralonsoh): there should be a better way to format the HTTP
        # response, adding the HTTP version to the ``webob.Response``
        # output string.
        out = request.http_version + ' ' + str(_res)
        if (int(_res.headers['content-length']) == 0 and
                _res.status_code == 200):
            # Add 2 extra \r\n to the result. HAProxy is also expecting
            # it even when the body is empty.
            out += '\r\n\r\n'
        return out.encode(http_response.encoding)

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
            LOG.warning(msg)
            title = '503 Service Unavailable'
            length = RESPONSE_LENGHT + len(title) * 2 + len(msg)
            reponse = RESPONSE.render(http_code=title, title=title,
                                      body_title=title, body=title, len=length)
            return encodeutils.to_utf8(reponse)

        if resp.status_code == 200:
            return self._http_response(resp, req)
        if resp.status_code == 403:
            LOG.warning(
                'The remote metadata server responded with Forbidden. This '
                'response usually occurs when shared secrets do not match.'
            )
            # TODO(ralonsoh): add info in the returned HTTP message to the VM.
            return self._http_response(resp, req)
        if resp.status_code == 500:
            msg = _(
                'Remote metadata server experienced an internal server error.'
            )
            LOG.warning(msg)
            # TODO(ralonsoh): add info in the returned HTTP message to the VM.
            return self._http_response(resp, req)
        if resp.status_code in (400, 404, 409, 502, 503, 504):
            # TODO(ralonsoh): add info in the returned HTTP message to the VM.
            return self._http_response(resp, req)
        raise Exception(_('Unexpected response code: %s') % resp.status_code)


class MetadataProxyHandler(MetadataProxyHandlerBaseSocketServer,
                           socketserver.StreamRequestHandler):
    NETWORK_ID_HEADER = 'X-Neutron-Network-ID'
    ROUTER_ID_HEADER = 'X-Neutron-Router-ID'
    _conf = None

    def __init__(self, request, client_address, server):
        self.plugin_rpc = MetadataPluginAPI(topics.PLUGIN)
        self.context = context.get_admin_context_without_session()
        super().__init__(self._conf, has_cache=False, request=request,
                         client_address=client_address, server=server)

    def handle(self):
        try:
            request = self.request.recv(4096)
            LOG.debug('Request: %s', request.decode('utf-8'))
            f_request = io.BytesIO(request)
            req = webob.Request.from_file(f_request)
            instance_id, project_id = self._get_instance_and_project_id(req)
            if instance_id:
                res = self._proxy_request(instance_id, project_id, req)
                self.wfile.write(res)
                return
            # TODO(ralonsoh): change this return to be a formatted Request
            # and added to self.wfile
            return webob_exc.HTTPNotFound()
        except Exception as exc:
            LOG.exception('Error while receiving data.')
            raise exc

    @staticmethod
    def _get_port_filters(router_id=None, ip_address=None,
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

    def _get_ports_from_server(self, router_id=None, ip_address=None,
                               networks=None, mac_address=None):
        """Get ports from server."""
        filters = self._get_port_filters(
            router_id, ip_address, networks, mac_address)
        return self.plugin_rpc.get_ports(self.context, filters)

    def _get_router_networks(self, router_id, skip_cache=False):
        """Find all networks connected to given router."""
        internal_ports = self._get_ports_from_server(router_id=router_id)
        return tuple(p['network_id'] for p in internal_ports)

    def _get_ports_for_remote_address(self, remote_address, networks,
                                      remote_mac=None,
                                      skip_cache=False):
        """Get list of ports that has given IP address and are part of
        given networks.

        :param remote_address: IP address to search for
        :param networks: List of networks in which the IP address will be
                         searched for
        :param remote_mac: Remote MAC to filter by, if given
        :param skip_cache: When to skip getting entry from cache

        """
        return self._get_ports_from_server(networks=networks,
                                           ip_address=remote_address,
                                           mac_address=remote_mac)

    def get_port(self, remote_address, network_id=None, remote_mac=None,
                 router_id=None, skip_cache=False):
        if network_id:
            networks = (network_id,)
        elif router_id:
            networks = self._get_router_networks(router_id,
                                                 skip_cache=skip_cache)
        else:
            raise TypeError(_("Either one of parameter network_id or router_id"
                              " must be passed to get_port method."))

        ports = self._get_ports_for_remote_address(remote_address, networks,
                                                   remote_mac=remote_mac,
                                                   skip_cache=skip_cache)
        LOG.debug("Got ports for remote_address %(remote_address)s, "
                  "network_id %(network_id)s, remote_mac %(remote_mac)s, "
                  "router_id %(router_id)s"
                  "%(ports)s",
                  {"remote_address": remote_address,
                   "network_id": network_id,
                   "remote_mac": remote_mac,
                   "router_id": router_id,
                   "ports": ports})
        num_ports = len(ports)
        if num_ports == 1:
            return ports[0]['device_id'], ports[0]['tenant_id']
        if num_ports == 0:
            LOG.error("No port found in network %s with IP address %s",
                      network_id, remote_address)
        return None, None


class UnixDomainMetadataProxy(proxy_base.UnixDomainMetadataProxyBase):

    def __init__(self, conf):
        super().__init__(conf)
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

    def run(self):
        file_socket = cfg.CONF.metadata_proxy_socket
        self._server = socketserver.ThreadingUnixStreamServer(
            file_socket, MetadataProxyHandler)
        MetadataProxyHandler._conf = self.conf
        self._server.serve_forever()

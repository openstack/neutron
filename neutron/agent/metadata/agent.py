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

import hashlib
import hmac

from neutron_lib.agent import topics
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import rpc as n_rpc
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall
from oslo_utils import encodeutils
import requests
import six
from six.moves import urllib
import webob

from neutron._i18n import _
from neutron.agent.linux import utils as agent_utils
from neutron.agent import rpc as agent_rpc
from neutron.common import cache_utils as cache
from neutron.common import constants as n_const
from neutron.common import ipv6_utils
from neutron.conf.agent.metadata import config

LOG = logging.getLogger(__name__)

MODE_MAP = {
    config.USER_MODE: 0o644,
    config.GROUP_MODE: 0o664,
    config.ALL_MODE: 0o666,
}


class MetadataPluginAPI(object):
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
        target = oslo_messaging.Target(
            topic=topic,
            namespace=n_const.RPC_NAMESPACE_METADATA,
            version='1.0')
        self.client = n_rpc.get_client(target)

    def get_ports(self, context, filters):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_ports', filters=filters)


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
                return self._proxy_request(instance_id, tenant_id, req)
            else:
                return webob.exc.HTTPNotFound()

        except Exception:
            LOG.exception("Unexpected error.")
            msg = _('An unknown error has occurred. '
                    'Please try your request again.')
            explanation = six.text_type(msg)
            return webob.exc.HTTPInternalServerError(explanation=explanation)

    def _get_ports_from_server(self, router_id=None, ip_address=None,
                               networks=None):
        """Get ports from server."""
        filters = self._get_port_filters(router_id, ip_address, networks)
        return self.plugin_rpc.get_ports(self.context, filters)

    def _get_port_filters(self, router_id=None, ip_address=None,
                          networks=None):
        filters = {}
        if router_id:
            filters['device_id'] = [router_id]
            filters['device_owner'] = constants.ROUTER_INTERFACE_OWNERS
        if ip_address:
            filters['fixed_ips'] = {'ip_address': [ip_address]}
        if networks:
            filters['network_id'] = networks

        return filters

    @cache.cache_method_results
    def _get_router_networks(self, router_id):
        """Find all networks connected to given router."""
        internal_ports = self._get_ports_from_server(router_id=router_id)
        return tuple(p['network_id'] for p in internal_ports)

    @cache.cache_method_results
    def _get_ports_for_remote_address(self, remote_address, networks):
        """Get list of ports that has given ip address and are part of
        given networks.

        :param networks: list of networks in which the ip address will be
                         searched for

        """
        return self._get_ports_from_server(networks=networks,
                                           ip_address=remote_address)

    def _get_ports(self, remote_address, network_id=None, router_id=None):
        """Search for all ports that contain passed ip address and belongs to
        given network.

        If no network is passed ports are searched on all networks connected to
        given router. Either one of network_id or router_id must be passed.

        """
        if network_id:
            networks = (network_id,)
        elif router_id:
            networks = self._get_router_networks(router_id)
        else:
            raise TypeError(_("Either one of parameter network_id or router_id"
                              " must be passed to _get_ports method."))

        return self._get_ports_for_remote_address(remote_address, networks)

    def _get_instance_and_tenant_id(self, req):
        remote_address = req.headers.get('X-Forwarded-For')
        network_id = req.headers.get('X-Neutron-Network-ID')
        router_id = req.headers.get('X-Neutron-Router-ID')

        ports = self._get_ports(remote_address, network_id, router_id)
        LOG.debug("Gotten ports for remote_address %(remote_address)s, "
                  "network_id %(network_id)s, router_id %(router_id)s are: "
                  "%(ports)s",
                  {"remote_address": remote_address,
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
            'X-Instance-ID-Signature': self._sign_instance_id(instance_id)
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

        resp = requests.request(method=req.method, url=url,
                                headers=headers,
                                data=req.body,
                                cert=client_cert,
                                verify=verify_cert)

        if resp.status_code == 200:
            req.response.content_type = resp.headers['content-type']
            req.response.body = resp.content
            LOG.debug(str(resp))
            return req.response
        elif resp.status_code == 403:
            LOG.warning(
                'The remote metadata server responded with Forbidden. This '
                'response usually occurs when shared secrets do not match.'
            )
            return webob.exc.HTTPForbidden()
        elif resp.status_code == 400:
            return webob.exc.HTTPBadRequest()
        elif resp.status_code == 404:
            return webob.exc.HTTPNotFound()
        elif resp.status_code == 409:
            return webob.exc.HTTPConflict()
        elif resp.status_code == 500:
            msg = _(
                'Remote metadata server experienced an internal server error.'
            )
            LOG.warning(msg)
            explanation = six.text_type(msg)
            return webob.exc.HTTPInternalServerError(explanation=explanation)
        else:
            raise Exception(_('Unexpected response code: %s') %
                            resp.status_code)

    def _sign_instance_id(self, instance_id):
        secret = self.conf.metadata_proxy_shared_secret
        secret = encodeutils.to_utf8(secret)
        instance_id = encodeutils.to_utf8(instance_id)
        return hmac.new(secret, instance_id, hashlib.sha256).hexdigest()


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
            'binary': 'neutron-metadata-agent',
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
        server = agent_utils.UnixDomainWSGIServer('neutron-metadata-agent')
        server.start(MetadataProxyHandler(self.conf),
                     self.conf.metadata_proxy_socket,
                     workers=self.conf.metadata_workers,
                     backlog=self.conf.metadata_backlog,
                     mode=self._get_socket_mode())
        self._init_state_reporting()
        server.wait()

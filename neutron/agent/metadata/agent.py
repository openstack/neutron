# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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
#
# @author: Mark McClain, DreamHost

import hashlib
import hmac
import os
import socket

import eventlet
import httplib2
from neutronclient.v2_0 import client
from oslo.config import cfg
import six.moves.urllib.parse as urlparse
import webob

from neutron.agent.common import config as agent_conf
from neutron.agent import rpc as agent_rpc
from neutron.common import config
from neutron.common import constants as n_const
from neutron.common import topics
from neutron.common import utils
from neutron import context
from neutron.openstack.common.cache import cache
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common import service
from neutron import wsgi

LOG = logging.getLogger(__name__)


class MetadataProxyHandler(object):
    OPTS = [
        cfg.StrOpt('admin_user',
                   help=_("Admin user")),
        cfg.StrOpt('admin_password',
                   help=_("Admin password"),
                   secret=True),
        cfg.StrOpt('admin_tenant_name',
                   help=_("Admin tenant name")),
        cfg.StrOpt('auth_url',
                   help=_("Authentication URL")),
        cfg.StrOpt('auth_strategy', default='keystone',
                   help=_("The type of authentication to use")),
        cfg.StrOpt('auth_region',
                   help=_("Authentication region")),
        cfg.BoolOpt('auth_insecure',
                    default=False,
                    help=_("Turn off verification of the certificate for"
                           " ssl")),
        cfg.StrOpt('auth_ca_cert',
                   default=None,
                   help=_("Certificate Authority public key (CA cert) "
                          "file for ssl")),
        cfg.StrOpt('endpoint_type',
                   default='adminURL',
                   help=_("Network service endpoint type to pull from "
                          "the keystone catalog")),
        cfg.StrOpt('nova_metadata_ip', default='127.0.0.1',
                   help=_("IP address used by Nova metadata server.")),
        cfg.IntOpt('nova_metadata_port',
                   default=8775,
                   help=_("TCP Port used by Nova metadata server.")),
        cfg.StrOpt('metadata_proxy_shared_secret',
                   default='',
                   help=_('Shared secret to sign instance-id request'),
                   secret=True)
    ]

    def __init__(self, conf):
        self.conf = conf
        self.auth_info = {}
        if self.conf.cache_url:
            self._cache = cache.get_cache(self.conf.cache_url)
        else:
            self._cache = False

    def _get_neutron_client(self):
        qclient = client.Client(
            username=self.conf.admin_user,
            password=self.conf.admin_password,
            tenant_name=self.conf.admin_tenant_name,
            auth_url=self.conf.auth_url,
            auth_strategy=self.conf.auth_strategy,
            region_name=self.conf.auth_region,
            token=self.auth_info.get('auth_token'),
            insecure=self.conf.auth_insecure,
            ca_cert=self.conf.auth_ca_cert,
            endpoint_url=self.auth_info.get('endpoint_url'),
            endpoint_type=self.conf.endpoint_type
        )
        return qclient

    @webob.dec.wsgify(RequestClass=webob.Request)
    def __call__(self, req):
        try:
            LOG.debug(_("Request: %s"), req)

            instance_id, tenant_id = self._get_instance_and_tenant_id(req)
            if instance_id:
                return self._proxy_request(instance_id, tenant_id, req)
            else:
                return webob.exc.HTTPNotFound()

        except Exception:
            LOG.exception(_("Unexpected error."))
            msg = _('An unknown error has occurred. '
                    'Please try your request again.')
            return webob.exc.HTTPInternalServerError(explanation=unicode(msg))

    @utils.cache_method_results
    def _get_router_networks(self, router_id):
        """Find all networks connected to given router."""
        qclient = self._get_neutron_client()

        internal_ports = qclient.list_ports(
            device_id=router_id,
            device_owner=n_const.DEVICE_OWNER_ROUTER_INTF)['ports']
        self.auth_info = qclient.get_auth_info()
        return tuple(p['network_id'] for p in internal_ports)

    @utils.cache_method_results
    def _get_ports_for_remote_address(self, remote_address, networks):
        """Get list of ports that has given ip address and are part of
        given networks.

        :param networks: list of networks in which the ip address will be
                         searched for

        """
        qclient = self._get_neutron_client()

        all_ports = qclient.list_ports(
            network_id=networks,
            fixed_ips=['ip_address=%s' % remote_address])['ports']
        self.auth_info = qclient.get_auth_info()
        return all_ports

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

        url = urlparse.urlunsplit((
            'http',
            '%s:%s' % (self.conf.nova_metadata_ip,
                       self.conf.nova_metadata_port),
            req.path_info,
            req.query_string,
            ''))

        h = httplib2.Http()
        resp, content = h.request(url, method=req.method, headers=headers,
                                  body=req.body)

        if resp.status == 200:
            LOG.debug(str(resp))
            req.response.content_type = resp['content-type']
            req.response.body = content
            return req.response
        elif resp.status == 403:
            msg = _(
                'The remote metadata server responded with Forbidden. This '
                'response usually occurs when shared secrets do not match.'
            )
            LOG.warn(msg)
            return webob.exc.HTTPForbidden()
        elif resp.status == 404:
            return webob.exc.HTTPNotFound()
        elif resp.status == 409:
            return webob.exc.HTTPConflict()
        elif resp.status == 500:
            msg = _(
                'Remote metadata server experienced an internal server error.'
            )
            LOG.warn(msg)
            return webob.exc.HTTPInternalServerError(explanation=unicode(msg))
        else:
            raise Exception(_('Unexpected response code: %s') % resp.status)

    def _sign_instance_id(self, instance_id):
        return hmac.new(self.conf.metadata_proxy_shared_secret,
                        instance_id,
                        hashlib.sha256).hexdigest()


class UnixDomainHttpProtocol(eventlet.wsgi.HttpProtocol):
    def __init__(self, request, client_address, server):
        if client_address == '':
            client_address = ('<local>', 0)
        # base class is old-style, so super does not work properly
        eventlet.wsgi.HttpProtocol.__init__(self, request, client_address,
                                            server)


class WorkerService(wsgi.WorkerService):
    def start(self):
        self._server = self._service.pool.spawn(self._service._run,
                                                self._application,
                                                self._service._socket)


class UnixDomainWSGIServer(wsgi.Server):
    def __init__(self, name):
        self._socket = None
        self._launcher = None
        self._server = None
        super(UnixDomainWSGIServer, self).__init__(name)

    def start(self, application, file_socket, workers, backlog):
        self._socket = eventlet.listen(file_socket,
                                       family=socket.AF_UNIX,
                                       backlog=backlog)
        if workers < 1:
            # For the case where only one process is required.
            self._server = self.pool.spawn_n(self._run, application,
                                             self._socket)
        else:
            # Minimize the cost of checking for child exit by extending the
            # wait interval past the default of 0.01s.
            self._launcher = service.ProcessLauncher(wait_interval=1.0)
            self._server = WorkerService(self, application)
            self._launcher.launch_service(self._server, workers=workers)

    def _run(self, application, socket):
        """Start a WSGI service in a new green thread."""
        logger = logging.getLogger('eventlet.wsgi.server')
        eventlet.wsgi.server(socket,
                             application,
                             custom_pool=self.pool,
                             protocol=UnixDomainHttpProtocol,
                             log=logging.WritableLogger(logger))


class UnixDomainMetadataProxy(object):
    OPTS = [
        cfg.StrOpt('metadata_proxy_socket',
                   default='$state_path/metadata_proxy',
                   help=_('Location for Metadata Proxy UNIX domain socket')),
        cfg.IntOpt('metadata_workers',
                   default=0,
                   help=_('Number of separate worker processes for metadata '
                          'server')),
        cfg.IntOpt('metadata_backlog',
                   default=128,
                   help=_('Number of backlog requests to configure the '
                          'metadata server socket with'))
    ]

    def __init__(self, conf):
        self.conf = conf

        dirname = os.path.dirname(cfg.CONF.metadata_proxy_socket)
        if os.path.isdir(dirname):
            try:
                os.unlink(cfg.CONF.metadata_proxy_socket)
            except OSError:
                with excutils.save_and_reraise_exception() as ctxt:
                    if not os.path.exists(cfg.CONF.metadata_proxy_socket):
                        ctxt.reraise = False
        else:
            os.makedirs(dirname, 0o755)

        self._init_state_reporting()

    def _init_state_reporting(self):
        self.context = context.get_admin_context_without_session()
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.agent_state = {
            'binary': 'neutron-metadata-agent',
            'host': cfg.CONF.host,
            'topic': 'N/A',
            'configurations': {
                'metadata_proxy_socket': cfg.CONF.metadata_proxy_socket,
                'nova_metadata_ip': cfg.CONF.nova_metadata_ip,
                'nova_metadata_port': cfg.CONF.nova_metadata_port,
            },
            'start_flag': True,
            'agent_type': n_const.AGENT_TYPE_METADATA}
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
            LOG.warn(_('Neutron server does not support state report.'
                       ' State report for this agent will be disabled.'))
            self.heartbeat.stop()
            return
        except Exception:
            LOG.exception(_("Failed reporting state!"))
            return
        self.agent_state.pop('start_flag', None)

    def run(self):
        server = UnixDomainWSGIServer('neutron-metadata-agent')
        server.start(MetadataProxyHandler(self.conf),
                     self.conf.metadata_proxy_socket,
                     workers=self.conf.metadata_workers,
                     backlog=self.conf.metadata_backlog)
        server.wait()


def main():
    eventlet.monkey_patch()
    cfg.CONF.register_opts(UnixDomainMetadataProxy.OPTS)
    cfg.CONF.register_opts(MetadataProxyHandler.OPTS)
    cache.register_oslo_configs(cfg.CONF)
    cfg.CONF.set_default(name='cache_url', default='')
    agent_conf.register_agent_state_opts_helper(cfg.CONF)
    cfg.CONF(project='neutron')
    config.setup_logging(cfg.CONF)
    utils.log_opt_values(LOG)
    proxy = UnixDomainMetadataProxy(cfg.CONF)
    proxy.run()

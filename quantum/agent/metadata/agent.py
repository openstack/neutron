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
import urlparse

import eventlet
import httplib2
from oslo.config import cfg
from quantumclient.v2_0 import client
import webob

from quantum.common import config
from quantum.common import utils
from quantum.openstack.common import log as logging
from quantum import wsgi

LOG = logging.getLogger(__name__)

DEVICE_OWNER_ROUTER_INTF = "network:router_interface"


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

    def _get_quantum_client(self):
        qclient = client.Client(
            username=self.conf.admin_user,
            password=self.conf.admin_password,
            tenant_name=self.conf.admin_tenant_name,
            auth_url=self.conf.auth_url,
            auth_strategy=self.conf.auth_strategy,
            region_name=self.conf.auth_region,
        )
        return qclient

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        try:
            LOG.debug(_("Request: %s"), req)

            instance_id = self._get_instance_id(req)
            if instance_id:
                return self._proxy_request(instance_id, req)
            else:
                return webob.exc.HTTPNotFound()

        except Exception:
            LOG.exception(_("Unexpected error."))
            msg = _('An unknown error has occurred. '
                    'Please try your request again.')
            return webob.exc.HTTPInternalServerError(explanation=unicode(msg))

    def _get_instance_id(self, req):
        qclient = self._get_quantum_client()

        remote_address = req.headers.get('X-Forwarded-For')
        network_id = req.headers.get('X-Quantum-Network-ID')
        router_id = req.headers.get('X-Quantum-Router-ID')

        if network_id:
            networks = [network_id]
        else:
            internal_ports = qclient.list_ports(
                device_id=router_id,
                device_owner=DEVICE_OWNER_ROUTER_INTF)['ports']

            networks = [p['network_id'] for p in internal_ports]

        ports = qclient.list_ports(
            network_id=networks,
            fixed_ips=['ip_address=%s' % remote_address])['ports']

        if len(ports) == 1:
            return ports[0]['device_id']

    def _proxy_request(self, instance_id, req):
        headers = {
            'X-Forwarded-For': req.headers.get('X-Forwarded-For'),
            'X-Instance-ID': instance_id,
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
        resp, content = h.request(url, headers=headers)

        if resp.status == 200:
            LOG.debug(str(resp))
            return content
        elif resp.status == 403:
            msg = _(
                'The remote metadata server responded with Forbidden. This '
                'response usually occurs when shared secrets do not match.'
            )
            LOG.warn(msg)
            return webob.exc.HTTPForbidden()
        elif resp.status == 404:
            return webob.exc.HTTPNotFound()
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
        # base class is old-style, no super does not work properly
        eventlet.wsgi.HttpProtocol.__init__(self, request, client_address,
                                            server)


class UnixDomainWSGIServer(wsgi.Server):
    def start(self, application, file_socket, backlog=128):
        sock = eventlet.listen(file_socket,
                               family=socket.AF_UNIX,
                               backlog=backlog)
        self.pool.spawn_n(self._run, application, sock)

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
                   help=_('Location for Metadata Proxy UNIX domain socket'))
    ]

    def __init__(self, conf):
        self.conf = conf

        dirname = os.path.dirname(cfg.CONF.metadata_proxy_socket)
        if os.path.isdir(dirname):
            try:
                os.unlink(cfg.CONF.metadata_proxy_socket)
            except OSError:
                if os.path.exists(cfg.CONF.metadata_proxy_socket):
                    raise
        else:
            os.makedirs(dirname, 0755)

    def run(self):
        server = UnixDomainWSGIServer('quantum-metadata-agent')
        server.start(MetadataProxyHandler(self.conf),
                     self.conf.metadata_proxy_socket)
        server.wait()


def main():
    eventlet.monkey_patch()
    cfg.CONF.register_opts(UnixDomainMetadataProxy.OPTS)
    cfg.CONF.register_opts(MetadataProxyHandler.OPTS)
    cfg.CONF(project='quantum')
    config.setup_logging(cfg.CONF)
    utils.log_opt_values(LOG)
    proxy = UnixDomainMetadataProxy(cfg.CONF)
    proxy.run()

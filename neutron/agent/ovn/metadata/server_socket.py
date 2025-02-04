# Copyright 2025 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import io
import socketserver
import urllib

import jinja2
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import encodeutils
import requests
import webob
from webob import exc as webob_exc

from neutron._i18n import _
from neutron.agent.linux import utils as agent_utils
from neutron.agent.metadata import proxy_base
from neutron.common import ipv6_utils
from neutron.common.ovn import constants as ovn_const
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
    NETWORK_ID_HEADER = 'X-OVN-Network-ID'
    ROUTER_ID_HEADER = ''
    _conf = None
    _chassis = None
    _sb_idl = None

    def __init__(self, request, client_address, server):
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

    @property
    def sb_idl(self):
        return self._sb_idl

    def get_port(self, remote_address, network_id=None, remote_mac=None,
                 router_id=None, skip_cache=False):
        ports = self.sb_idl.get_network_port_bindings_by_ip(network_id,
                                                            remote_address,
                                                            mac=remote_mac)
        num_ports = len(ports)
        if num_ports == 1:
            external_ids = ports[0].external_ids
            return (external_ids[ovn_const.OVN_DEVID_EXT_ID_KEY],
                    external_ids[ovn_const.OVN_PROJID_EXT_ID_KEY])
        if num_ports == 0:
            LOG.error("No port found in network %s with IP address %s",
                      network_id, remote_address)
        elif num_ports > 1:
            port_uuids = ', '.join([str(port.uuid) for port in ports])
            LOG.error("More than one port found in network %s with IP address "
                      "%s. Please run the neutron-ovn-db-sync-util script as "
                      "there seems to be inconsistent data between Neutron "
                      "and OVN databases. OVN Port uuids: %s", network_id,
                      remote_address, port_uuids)
        return None, None


class UnixDomainMetadataProxy(proxy_base.UnixDomainMetadataProxyBase):
    def __init__(self, conf, chassis, sb_idl=None):
        super().__init__(conf)
        self.chassis = chassis
        self.sb_idl = sb_idl
        agent_utils.ensure_directory_exists_without_file(
            cfg.CONF.metadata_proxy_socket)
        self._server = None

    def run(self):
        file_socket = cfg.CONF.metadata_proxy_socket
        self._server = socketserver.ThreadingUnixStreamServer(
            file_socket, MetadataProxyHandler)
        MetadataProxyHandler._conf = self.conf
        MetadataProxyHandler._chassis = self.chassis
        MetadataProxyHandler._sb_idl = self.sb_idl

    def wait(self):
        self._server.serve_forever()

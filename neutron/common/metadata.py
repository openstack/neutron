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
import io
import socketserver
from urllib import parse

import jinja2
from neutron_lib import constants
from oslo_log import log as logging
from oslo_utils import encodeutils
import requests
import webob

from neutron._i18n import _
from neutron.agent.metadata import proxy_base
from neutron.common import ipv6_utils
from neutron.common import utils as common_utils


LOG = logging.getLogger(__name__)


PROXY_SERVICE_NAME = 'haproxy'
PROXY_SERVICE_CMD = 'haproxy'

CONTENT_ENCODERS = ('gzip', 'deflate')


class InvalidUserOrGroupException(Exception):
    pass


METADATA_HAPROXY_GLOBAL = """
global
    log         /dev/log local0 %(log_level)s
    log-tag     %(log_tag)s
    user        %(user)s
    group       %(group)s
    maxconn     1024
    nbthread    2
    pidfile     %(pidfile)s
    daemon

defaults
    log global
    mode http
    option httplog
    option dontlognull
    option http-server-close
    option forwardfor
    retries                 3
    timeout http-request    30s
    timeout connect         30s
    timeout client          32s
    timeout server          32s
    timeout http-keep-alive 30s
"""

RATE_LIMITED_CONFIG_TEMPLATE = """
backend base_rate_limiter
    stick-table type %(ip_version)s size 10k expire %(stick_table_expire)ss store http_req_rate(%(base_window_duration)ss)

backend burst_rate_limiter
    stick-table type %(ip_version)s size 10k expire %(stick_table_expire)ss store http_req_rate(%(burst_window_duration)ss)

listen listener
    bind %(host)s:%(port)s
    %(bind_v6_line)s

    http-request track-sc0 src table base_rate_limiter
    http-request track-sc1 src table burst_rate_limiter
    http-request deny deny_status 429 if { src_http_req_rate(base_rate_limiter) gt %(base_query_rate_limit)s }
    http-request deny deny_status 429 if { src_http_req_rate(burst_rate_limiter) gt %(burst_query_rate_limit)s }

    server metadata %(unix_socket_path)s
"""  # noqa: E501 line-length

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
RESPONSE_LENGTH = 95


def parse_ip_versions(ip_versions):
    if not set(ip_versions).issubset({constants.IP_VERSION_4,
                                      constants.IP_VERSION_6}):
        LOG.warning('Invalid metadata address IP versions: %s. Metadata rate '
                    'limiting will not be enabled.', ip_versions)
        return
    if len(ip_versions) != 1:
        LOG.warning('Invalid metadata address IP versions: %s. Metadata rate '
                    'limiting cannot be enabled for IPv4 and IPv6 at the same '
                    'time. Metadata rate limiting will not be enabled.',
                    ip_versions)
        return
    return ip_versions[0]


def get_haproxy_config(cfg_info, rate_limiting_config, header_config_template,
                       unlimited_config_template):
    ip_version = parse_ip_versions(rate_limiting_config.ip_versions)
    if rate_limiting_config.rate_limit_enabled and ip_version:
        cfg_info['ip_version'] = (
            'ipv6' if ip_version == 6 else 'ip')
        cfg_info['base_window_duration'] = (
            rate_limiting_config['base_window_duration'])
        cfg_info['base_query_rate_limit'] = (
            rate_limiting_config['base_query_rate_limit'])
        cfg_info['burst_window_duration'] = (
            rate_limiting_config['burst_window_duration'])
        cfg_info['burst_query_rate_limit'] = (
            rate_limiting_config['burst_query_rate_limit'])
        cfg_info['stick_table_expire'] = max(
            rate_limiting_config['base_window_duration'],
            rate_limiting_config['burst_window_duration'])
        FINAL_CONFIG_TEMPLATE = (METADATA_HAPROXY_GLOBAL +
                                 RATE_LIMITED_CONFIG_TEMPLATE +
                                 header_config_template)
    else:
        FINAL_CONFIG_TEMPLATE = (METADATA_HAPROXY_GLOBAL +
                                 unlimited_config_template +
                                 header_config_template)

    return FINAL_CONFIG_TEMPLATE % cfg_info


def encode_http_reponse(http_code, title, message):
    """Return an encoded HTTP, providing the HTTP code, title and message"""
    length = RESPONSE_LENGTH + len(title) * 2 + len(message)
    reponse = RESPONSE.render(http_code=http_code, title=title,
                              body_title=title, body=message, len=length)
    return encodeutils.to_utf8(reponse)


class MetadataProxyHandlerBaseSocketServer(
        proxy_base.MetadataProxyHandlerBase,
        socketserver.StreamRequestHandler,
        metaclass=abc.ABCMeta):
    @staticmethod
    def _http_response(http_response, request):
        _res = webob.Response(
            body=http_response.content,
            status=http_response.status_code,
            content_type=http_response.headers['content-type'],
            charset=http_response.encoding)
        # The content of the response is decoded depending on the
        # "Context-Enconding" header, if present. The operation is limited to
        # ("gzip", "deflate"), as is in the ``webob.response.Response`` class.
        if _res.content_encoding in CONTENT_ENCODERS:
            _res.decode_content()

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

        url = parse.urlunsplit((
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
            return encode_http_reponse(title, title, msg)

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

            network_id, router_id = self._get_instance_id(req)
            if network_id and router_id:
                title = '400 Bad Request'
                msg = (_('Both network %(network)s and router %(router)s '
                         'defined.') %
                         {'network': network_id, 'router': router_id})
                LOG.warning(msg)
            elif network_id:
                title = '404 Not Found'
                msg = _('Instance was not found on network %s.') % network_id
                LOG.warning(msg)
            else:
                title = '404 Not Found'
                msg = _('Instance was not found on router %s.') % router_id
                LOG.warning(msg)
            res = encode_http_reponse(title, title, msg)
            self.wfile.write(res)
        except Exception as exc:
            LOG.exception('Error while receiving data.')
            raise exc

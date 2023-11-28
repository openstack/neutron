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

from neutron_lib import constants
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


PROXY_SERVICE_NAME = 'haproxy'
PROXY_SERVICE_CMD = 'haproxy'


class InvalidUserOrGroupException(Exception):
    pass


METADATA_HAPROXY_GLOBAL = """
global
    log         /dev/log local0 %(log_level)s
    log-tag     %(log_tag)s
    user        %(user)s
    group       %(group)s
    maxconn     1024
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

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

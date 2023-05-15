# Copyright (c) 2022 China Unicom Cloud Data Co.,Ltd.
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

import grp
import io
import os
import pwd

import jinja2
from neutron_lib.utils import file as file_utils
from oslo_config import cfg
from oslo_log import log as logging

from neutron._i18n import _
from neutron.agent.linux import external_process
from neutron.agent.linux import utils
from neutron.common import metadata as common_meta
from neutron.common import utils as common_utils

LOG = logging.getLogger(__name__)

PROXY_SERVICE_NAME = common_meta.PROXY_SERVICE_NAME
PROXY_SERVICE_CMD = common_meta.PROXY_SERVICE_CMD

_HOST_PATH_PROXY_TEMPLATE = jinja2.Template("""
global
    log         /dev/log local0 {{ log_level }}
    log-tag     {{ log_tag }}
    user        {{ user }}
    group       {{ group }}
    maxconn     {{ maxconn }}
    daemon

frontend public
    bind            *:80 name clear
    mode            http
    log             global
    option          httplog
    option          dontlognull
    maxconn         {{ maxconn }}
    timeout http-request    30s
    timeout connect         30s
    timeout client          32s
    timeout server          32s
    timeout http-keep-alive 30s

    monitor-uri     /monitoruri
    stats uri       /admin/stats
{% for instance in instance_list %}
    acl instance_{{ instance.uuid }}_{{ instance.provider_ip
    }} src {{ instance.provider_ip }}
{% endfor %}

{% for instance in instance_list %}
    use_backend backend_{{ instance.uuid }}_{{
    instance.provider_ip }} if instance_{{ instance.uuid }}_{{
    instance.provider_ip }}
{% endfor %}

{% for instance in instance_list %}
backend backend_{{ instance.uuid }}_{{ instance.provider_ip }}
    mode            http
    balance         roundrobin
    retries         3
    option redispatch
    timeout http-request    30s
    timeout connect         30s
    timeout server          30s

    http-request set-header X-Instance-ID {{ instance.uuid }}
    http-request set-header X-Tenant-ID {{ instance.project_id }}
    http-request set-header X-Instance-ID-Signature {{ instance.signature }}

    server metasrv {{ meta_api }}

{% endfor %}
""")


class ProxyInstance(object):
    def __init__(self, instance_id, provider_ip, project_id):
        self.uuid = instance_id
        self.provider_ip = provider_ip
        self.project_id = project_id
        self.signature = common_utils.sign_instance_id(
            cfg.CONF.METADATA, self.uuid)


class HostMedataHAProxyDaemonMonitor(object):
    """Manage the data and state of a host metadata haproxy process."""

    def __init__(self, process_monitor, uuid=None,
                 user=None, group=None):
        self._host_id = uuid or "host_metadata_proxy"
        self._process_monitor = process_monitor
        self.haproxy_conf = None
        self.user = user or str(os.geteuid())
        self.group = group or str(os.getegid())

    def _generate_proxy_conf(self, instance_infos):
        haproxy_conf = utils.get_conf_file_name(
            cfg.CONF.state_path, self._host_id,
            'haproxy.conf', True)
        buf = io.StringIO()
        meta_api = "%s:%s" % (
            cfg.CONF.METADATA.nova_metadata_host,
            cfg.CONF.METADATA.nova_metadata_port)

        try:
            username = pwd.getpwuid(int(self.user)).pw_name
        except (ValueError, KeyError):
            try:
                username = pwd.getpwnam(self.user).pw_name
            except KeyError:
                raise common_meta.InvalidUserOrGroupException(
                    _("Invalid user/uid: '%s'") % self.user)

        try:
            groupname = grp.getgrgid(int(self.group)).gr_name
        except (ValueError, KeyError):
            try:
                groupname = grp.getgrnam(self.group).gr_name
            except KeyError:
                raise common_meta.InvalidUserOrGroupException(
                    _("Invalid group/gid: '%s'") % self.group)

        buf.write('%s' % _HOST_PATH_PROXY_TEMPLATE.render(
            log_level='debug',
            log_tag="%s-%s" % (PROXY_SERVICE_NAME, self._host_id),
            user=username,
            group=groupname,
            maxconn=1024,
            instance_list=instance_infos,
            meta_api=meta_api))

        contents = buf.getvalue()
        LOG.debug("Host metadata haproxy config = %s", contents)
        file_utils.replace_file(haproxy_conf, contents)
        return haproxy_conf

    def _get_proxy_process_manager(self, callback=None):
        return external_process.ProcessManager(
            conf=cfg.CONF,
            uuid=self._host_id,
            service=PROXY_SERVICE_NAME,
            default_cmd_callback=callback,
            run_as_root=True)

    def _spawn_proxy(self, haproxy_conf):
        def callback(pid_file):
            proxy_cmd = [PROXY_SERVICE_NAME, '-f', '%s' % haproxy_conf,
                         '-p', '%s' % pid_file]
            return proxy_cmd

        pm = self._get_proxy_process_manager(callback)
        pm.enable(reload_cfg=True)
        self._process_monitor.register(uuid=self._host_id,
                                       service_name=PROXY_SERVICE_NAME,
                                       monitored_process=pm)
        LOG.debug("Host metadata proxy enabled for host %s", self._host_id)

    def config(self, instance_infos):
        infos = []
        for info in instance_infos:
            infos.append(ProxyInstance(info['instance_id'],
                                       info['provider_ip'],
                                       info['project_id']))
        if infos:
            self.haproxy_conf = self._generate_proxy_conf(infos)

    def enable(self):
        if self.haproxy_conf:
            self._spawn_proxy(self.haproxy_conf)
            return

        self.disable()

    def disable(self):
        self._process_monitor.unregister(uuid=self._host_id,
                                         service_name=PROXY_SERVICE_NAME)
        pm = self._get_proxy_process_manager()
        pm.disable()
        utils.remove_conf_files(cfg.CONF.state_path, self._host_id)
        LOG.debug("Host metadata proxy disabled for host %s", self._host_id)

    @property
    def enabled(self):
        return self._get_proxy_process_manager().active

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

from unittest import mock

from oslo_config import cfg

from neutron.agent.l2.extensions.metadata import host_metadata_proxy
from neutron.agent.linux import external_process
from neutron.tests import base


class TestHostMedataHAProxyDaemonMonitor(base.BaseTestCase):

    def setUp(self):
        super(TestHostMedataHAProxyDaemonMonitor, self).setUp()

        self.ensure_dir = mock.patch(
            'oslo_utils.fileutils.ensure_tree').start()

        self.utils_exec_p = mock.patch(
            'neutron.agent.linux.utils.execute')
        self.utils_exec = self.utils_exec_p.start()

        self.delete_if_exists = mock.patch(
            'neutron.agent.linux.utils.delete_if_exists').start()

        self.utils_replace_file_p = mock.patch(
            'neutron_lib.utils.file.replace_file')
        self.utils_replace_file = self.utils_replace_file_p.start()

    def test_spawn_host_metadata_haproxy(self):
        cfg.CONF.set_override('metadata_proxy_shared_secret',
                              'secret', group='METADATA')
        conffile = '/fake/host_metadata_proxy.haproxy.conf'
        pidfile = '/fake/host_metadata_proxy.pid.haproxy'
        process_monitor = external_process.ProcessMonitor(
            config=cfg.CONF,
            resource_type='MetadataPath')

        get_conf_file_name = 'neutron.agent.linux.utils.get_conf_file_name'
        get_pid_file_name = ('neutron.agent.linux.external_process.'
                             'ProcessManager.get_pid_file_name')
        utils_execute = 'neutron.agent.common.utils.execute'

        mock.patch(get_conf_file_name).start().return_value = conffile
        mock.patch(get_pid_file_name).start().return_value = pidfile
        execute = mock.patch(utils_execute).start()

        host_meta = host_metadata_proxy.HostMedataHAProxyDaemonMonitor(
            process_monitor)
        instance_infos = [
            {"instance_id": "uuid1",
             "provider_ip": "1.1.1.1",
             "project_id": "project1"}]
        host_meta.config(instance_infos)
        host_meta.enable()
        cmd = execute.call_args[0][0]
        _join = lambda *args: ' '.join(args)
        cmd = _join(*cmd)
        self.assertIn('haproxy', cmd)
        self.assertIn(_join('-f', conffile), cmd)
        self.assertIn(_join('-p', pidfile), cmd)
        self.delete_if_exists.assert_called_once_with(pidfile,
                                                      run_as_root=True)

    def test_generate_host_metadata_haproxy_config(self):
        cfg.CONF.set_override('metadata_proxy_shared_secret',
                              'secret', group='METADATA')
        sig = (
            "3b5421875d7ba0fc910202f5ce448d9419597e7b66f702b53335116fee60e81e")
        cfg.CONF.set_override('nova_metadata_host',
                              '2.2.2.2',
                              group='METADATA')
        cfg.CONF.set_override('nova_metadata_port',
                              '8775',
                              group='METADATA')
        process_monitor = external_process.ProcessMonitor(
            config=cfg.CONF,
            resource_type='MetadataPath')
        host_meta = host_metadata_proxy.HostMedataHAProxyDaemonMonitor(
            process_monitor)
        instance_infos = [
            host_metadata_proxy.ProxyInstance('uuid1', '1.1.1.1', 'project1')]
        host_meta._generate_proxy_conf(instance_infos)
        acl = "acl instance_uuid1_1.1.1.1 src 1.1.1.1"
        use_acl = "use_backend backend_uuid1_1.1.1.1 if instance_uuid1_1.1.1.1"
        backend = "backend backend_uuid1_1.1.1.1"
        http_hd_ins_id = "http-request set-header X-Instance-ID uuid1"
        http_hd_pj = "http-request set-header X-Tenant-ID project1"
        http_hd_sig = (
            "http-request set-header X-Instance-ID-Signature %s" % sig)
        meta_real_srv = "server metasrv 2.2.2.2:8775"
        expects = [acl, use_acl, backend, http_hd_ins_id, http_hd_pj,
                   http_hd_sig, meta_real_srv]
        for exp in expects:
            self.assertIn(exp, self.utils_replace_file.call_args[0][1])

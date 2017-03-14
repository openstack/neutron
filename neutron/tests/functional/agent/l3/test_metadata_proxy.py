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

import functools
import os.path
import time

import fixtures
from oslo_config import cfg
import webob
import webob.dec
import webob.exc

from neutron.agent.linux import dhcp
from neutron.agent.linux import external_process
from neutron.agent.linux import utils
from neutron.tests.common import machine_fixtures
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.l3 import framework
from neutron.tests.functional.agent.linux import helpers
from neutron.tests.functional.agent.linux import simple_daemon

METADATA_REQUEST_TIMEOUT = 60
METADATA_REQUEST_SLEEP = 5


class MetadataFakeProxyHandler(object):

    def __init__(self, status):
        self.status = status

    @webob.dec.wsgify()
    def __call__(self, req):
        return webob.Response(status=self.status)


class MetadataL3AgentTestCase(framework.L3AgentTestFramework):

    SOCKET_MODE = 0o644

    def _create_metadata_fake_server(self, status):
        server = utils.UnixDomainWSGIServer('metadata-fake-server')
        self.addCleanup(server.stop)

        # NOTE(cbrandily): TempDir fixture creates a folder with 0o700
        # permissions but metadata_proxy_socket folder must be readable by all
        # users
        self.useFixture(
            helpers.RecursivePermDirFixture(
                os.path.dirname(self.agent.conf.metadata_proxy_socket), 0o555))
        server.start(MetadataFakeProxyHandler(status),
                     self.agent.conf.metadata_proxy_socket,
                     workers=0, backlog=4096, mode=self.SOCKET_MODE)

    def _query_metadata_proxy(self, machine):
        url = 'http://%(host)s:%(port)s' % {'host': dhcp.METADATA_DEFAULT_IP,
                                            'port': dhcp.METADATA_PORT}
        cmd = 'curl', '--max-time', METADATA_REQUEST_TIMEOUT, '-D-', url
        i = 0
        CONNECTION_REFUSED_TIMEOUT = METADATA_REQUEST_TIMEOUT // 2
        while i <= CONNECTION_REFUSED_TIMEOUT:
            try:
                raw_headers = machine.execute(cmd)
                break
            except RuntimeError as e:
                if 'Connection refused' in str(e):
                    time.sleep(METADATA_REQUEST_SLEEP)
                    i += METADATA_REQUEST_SLEEP
                else:
                    self.fail('metadata proxy unreachable '
                              'on %s before timeout' % url)

        if i > CONNECTION_REFUSED_TIMEOUT:
            self.fail('Timed out waiting metadata proxy to become available')
        return raw_headers.splitlines()[0]

    def test_access_to_metadata_proxy(self):
        """Test access to the l3-agent metadata proxy.

        The test creates:
         * A l3-agent metadata service:
           * A router (which creates a metadata proxy in the router namespace),
           * A fake metadata server
         * A "client" namespace (simulating a vm) with a port on router
           internal subnet.

        The test queries from the "client" namespace the metadata proxy on
        http://169.254.169.254 and asserts that the metadata proxy added
        the X-Forwarded-For and X-Neutron-Router-Id headers to the request
        and forwarded the http request to the fake metadata server and the
        response to the "client" namespace.
        """
        router_info = self.generate_router_info(enable_ha=False)
        router = self.manage_router(self.agent, router_info)
        self._create_metadata_fake_server(webob.exc.HTTPOk.code)

        # Create and configure client namespace
        router_ip_cidr = self._port_first_ip_cidr(router.internal_ports[0])
        br_int = framework.get_ovs_bridge(
            self.agent.conf.ovs_integration_bridge)

        machine = self.useFixture(
            machine_fixtures.FakeMachine(
                br_int,
                net_helpers.increment_ip_cidr(router_ip_cidr),
                router_ip_cidr.partition('/')[0]))

        # Query metadata proxy
        firstline = self._query_metadata_proxy(machine)

        # Check status code
        self.assertIn(str(webob.exc.HTTPOk.code), firstline.split())

    @staticmethod
    def _make_cmdline_callback(uuid):
        def _cmdline_callback(pidfile):
            cmdline = ["python", simple_daemon.__file__,
                       "--uuid=%s" % uuid,
                       "--pid_file=%s" % pidfile]
            return cmdline
        return _cmdline_callback

    def test_haproxy_migration_path(self):
        """Test the migration path for haproxy.

        This test will launch the simple_daemon Python process before spawning
        haproxy. When launching haproxy, it will be detected and killed, as
        it's running on the same pidfile and with the router uuid in its
        cmdline.
        """
        # Make sure that external_pids configuration option is the same for
        # simple_daemon and haproxy so that both work on the same pid_file.
        get_temp_file_path = functools.partial(
            self.get_temp_file_path,
            root=self.useFixture(fixtures.TempDir()))
        cfg.CONF.set_override('external_pids',
                              get_temp_file_path('external/pids'))
        self.agent.conf.set_override('external_pids',
                                     get_temp_file_path('external/pids'))

        router_info = self.generate_router_info(enable_ha=False)

        # Spawn the simple_daemon process in the background using the generated
        # router uuid. We are not registering it within ProcessMonitor so that
        # it doesn't get respawned once killed.
        _callback = self._make_cmdline_callback(router_info['id'])
        pm = external_process.ProcessManager(
            conf=cfg.CONF,
            uuid=router_info['id'],
            default_cmd_callback=_callback)
        pm.enable()
        self.addCleanup(pm.disable)

        # Make sure that simple_daemon is running
        self.assertIn('simple_daemon', pm.cmdline)

        # Create the router. This is expected to launch haproxy after killing
        # the simple_daemon process.
        self.manage_router(self.agent, router_info)

        # Make sure that it was killed and replaced by haproxy
        self.assertNotIn('simple_daemon', pm.cmdline)
        self.assertIn('haproxy', pm.cmdline)


class UnprivilegedUserMetadataL3AgentTestCase(MetadataL3AgentTestCase):
    """Test metadata proxy with least privileged user.

    The least privileged user has uid=65534 and is commonly named 'nobody' but
    not always, that's why we use its uid.
    """

    SOCKET_MODE = 0o664

    def setUp(self):
        super(UnprivilegedUserMetadataL3AgentTestCase, self).setUp()
        self.agent.conf.set_override('metadata_proxy_user', '65534')


class UnprivilegedUserGroupMetadataL3AgentTestCase(MetadataL3AgentTestCase):
    """Test metadata proxy with least privileged user/group.

    The least privileged user has uid=65534 and is commonly named 'nobody' but
    not always, that's why we use its uid.
    Its group has gid=65534 and is commonly named 'nobody' or 'nogroup', that's
    why we use its gid.
    """

    SOCKET_MODE = 0o666

    def setUp(self):
        super(UnprivilegedUserGroupMetadataL3AgentTestCase, self).setUp()
        self.agent.conf.set_override('metadata_proxy_user', '65534')
        self.agent.conf.set_override('metadata_proxy_group', '65534')

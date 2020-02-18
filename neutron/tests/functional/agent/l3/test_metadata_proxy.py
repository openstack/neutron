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

import os.path
import time

import webob
import webob.dec
import webob.exc

from neutron.agent.linux import dhcp
from neutron.agent.linux import utils
from neutron.tests.common import machine_fixtures
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.l3 import framework
from neutron.tests.functional.agent.linux import helpers

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
            self.agent.conf.OVS.integration_bridge)

        machine = self.useFixture(
            machine_fixtures.FakeMachine(
                br_int,
                net_helpers.increment_ip_cidr(router_ip_cidr),
                router_ip_cidr.partition('/')[0]))

        # Query metadata proxy
        firstline = self._query_metadata_proxy(machine)

        # Check status code
        self.assertIn(str(webob.exc.HTTPOk.code), firstline.split())


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

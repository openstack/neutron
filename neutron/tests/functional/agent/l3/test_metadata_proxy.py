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

import netaddr
from neutron_lib import constants
from oslo_log import log as logging
import webob
import webob.dec
import webob.exc

from neutron.agent.linux import ip_lib
from neutron.tests.common import machine_fixtures
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.l3 import framework
from neutron.tests.functional.agent.linux import helpers

LOG = logging.getLogger(__name__)

METADATA_REQUEST_TIMEOUT = 60
METADATA_REQUEST_SLEEP = 5
TOO_MANY_REQUESTS_CODE = '429'


class MetadataFakeProxyHandler:

    def __init__(self, status):
        self.status = status

    @webob.dec.wsgify()
    def __call__(self, req):
        return webob.Response(status=self.status)


class MetadataL3AgentTestCase(framework.L3AgentTestFramework):
    """Test access to the l3-agent metadata proxy.

    The test cases in this class create:
     * A l3-agent metadata service:
       * A router (which creates a metadata proxy in the router namespace),
       * A fake metadata server
     * A "client" namespace (simulating a vm) with a port on router
       internal subnet.

    The test cases query from the "client" namespace the metadata proxy on
    http://169.254.169.254 or http://[fe80::a9fe:a9fe] and assert that the
    metadata proxy forwarded successfully the http request to the fake metadata
    server and a 200 (OK) response was sent to the "client" namespace. Some of
    the test cases additionally test the metadata proxy rate limiting, by
    asserting that, after a requests limit is exceeded, the "client" namespace
    receives a 429 (Too Many Requests) response.
    """

    SOCKET_MODE = 0o644

    def setUp(self):
        self.skipTest('Skip test until eventlet is removed')

    def _create_metadata_fake_server(self, status):
        # NOTE(ralonsoh): this section must be refactored once eventlet is
        # removed. ``UnixDomainWSGIServer`` is no longer used.
        # server = utils.UnixDomainWSGIServer('metadata-fake-server')
        # self.addCleanup(server.stop)

        # NOTE(cbrandily): TempDir fixture creates a folder with 0o700
        # permissions but metadata_proxy_socket folder must be readable by all
        # users
        self.useFixture(
            helpers.RecursivePermDirFixture(
                os.path.dirname(self.agent.conf.metadata_proxy_socket), 0o555))
        # server.start(MetadataFakeProxyHandler(status),
        #              self.agent.conf.metadata_proxy_socket,
        #              workers=0, backlog=4096, mode=self.SOCKET_MODE)

    def _get_command(self, machine, ipv6=False, interface=None):
        if ipv6:
            params = {'host': constants.METADATA_V6_IP,
                      'interface': interface,
                      'port': constants.METADATA_PORT}
            url = 'http://[%(host)s%%%(interface)s]:%(port)s' % params
        else:
            params = {'host': constants.METADATA_V4_IP,
                      'port': constants.METADATA_PORT}
            url = 'http://%(host)s:%(port)s' % params
        return 'curl', '--max-time', METADATA_REQUEST_TIMEOUT, '-D-', url

    def _setup_for_ipv6(self, machine, qr_lla):
        lla_info = (machine.port.addr.list(scope='link',
                                           ip_version=6)[0])
        interface = lla_info['name']
        machine.port.addr.wait_until_address_ready(
            lla_info['cidr'].split('/')[0])
        machine.execute(('ip', '-6', 'route', 'add',
                         constants.METADATA_V6_IP, 'via', qr_lla, 'dev',
                         interface,))
        return interface

    def _log_router_interfaces_configuration(self, router):
        router_ip_wrapper = ip_lib.IPWrapper(router.ns_name)
        ip_a_output = router_ip_wrapper.netns.execute(["ip", "addr"])
        LOG.debug("Interfaces in the router namespace (%s): %s",
                  router.ns_name, ip_a_output)

    def _query_metadata_proxy(self, machine, ipv6=False, interface=None,
                              router=None):
        cmd = self._get_command(machine, ipv6, interface)
        i = 0
        CONNECTION_REFUSED_TIMEOUT = METADATA_REQUEST_TIMEOUT // 2
        while i <= CONNECTION_REFUSED_TIMEOUT:
            try:
                raw_headers = machine.execute(cmd)
                break
            except RuntimeError as e:
                if 'Connection refused' not in str(e):
                    if router:
                        self._log_router_interfaces_configuration(router)

                    self.fail(
                        'metadata proxy unreachable on %s before timeout' %
                        cmd[-1])
                time.sleep(METADATA_REQUEST_SLEEP)
                i += METADATA_REQUEST_SLEEP

        if i > CONNECTION_REFUSED_TIMEOUT:
            self.fail('Timed out waiting metadata proxy to become available')
        return raw_headers.splitlines()[0]

    def _create_resources(self):
        router_info = self.generate_router_info(enable_ha=False,
                                                dual_stack=True)
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
        router_ifs = router_info[constants.INTERFACE_KEY]
        qr_lla = str(
            netaddr.EUI(router_ifs[0]['mac_address']).ipv6_link_local())
        return machine, qr_lla, router

    def _test_access_to_metadata_proxy(self, ipv6=False):
        machine, qr_lla, router = self._create_resources()
        interface = self._setup_for_ipv6(machine, qr_lla) if ipv6 else None

        # Query metadata proxy
        firstline = self._query_metadata_proxy(machine, ipv6=ipv6,
                                               interface=interface,
                                               router=router)

        # Check status code
        self.assertIn(str(webob.exc.HTTPOk.code), firstline.split())

    def _set_up_for_rate_limiting_test(self, ipv6=False):
        self.conf.set_override('rate_limit_enabled', True,
                               'metadata_rate_limiting')
        if ipv6:
            self.conf.set_override('ip_versions', [6],
                                   'metadata_rate_limiting')
        machine, qr_lla, router = self._create_resources()
        interface = self._setup_for_ipv6(machine, qr_lla) if ipv6 else None
        return machine, interface, router

    def _test_rate_limiting(self, limit, machine, ipv6=False, interface=None,
                            exceed=True, router=None):
        # The first "limit" requests should succeed
        for _ in range(limit):
            firstline = self._query_metadata_proxy(machine, ipv6=ipv6,
                                                   interface=interface,
                                                   router=router)
            self.assertIn(str(webob.exc.HTTPOk.code), firstline.split())

        if exceed:
            firstline = self._query_metadata_proxy(machine, ipv6=ipv6,
                                                   interface=interface,
                                                   router=router)
            self.assertIn(TOO_MANY_REQUESTS_CODE, firstline.split())

    def test_access_to_metadata_proxy(self):
        self._test_access_to_metadata_proxy()

    def test_access_to_metadata_proxy_ipv6(self):
        self._test_access_to_metadata_proxy(ipv6=True)

    def test_metadata_proxy_rate_limiting(self):
        self.conf.set_override('base_query_rate_limit', 2,
                               'metadata_rate_limiting')
        machine, _, _ = self._set_up_for_rate_limiting_test()
        self._test_rate_limiting(2, machine)

    def test_metadata_proxy_rate_limiting_ipv6(self):
        self.conf.set_override('base_query_rate_limit', 2,
                               'metadata_rate_limiting')
        machine, interface, router = self._set_up_for_rate_limiting_test(
            ipv6=True)
        self._test_rate_limiting(2, machine, ipv6=True, interface=interface,
                                 router=router)

    def test_metadata_proxy_burst_rate_limiting(self):
        self.conf.set_override('base_query_rate_limit', 10,
                               'metadata_rate_limiting')
        self.conf.set_override('base_window_duration', 60,
                               'metadata_rate_limiting')
        self.conf.set_override('burst_query_rate_limit', 2,
                               'metadata_rate_limiting')
        self.conf.set_override('burst_window_duration', 5,
                               'metadata_rate_limiting')
        machine, _, _ = self._set_up_for_rate_limiting_test()

        # Since the number of metadata requests don't exceed the base or the
        # burst query rate limit, all of them should get "OK" response
        self._test_rate_limiting(2, machine, exceed=False)

        # Wait for haproxy to reset the burst window and then test it returns
        # "Too Many Requests" after exceeding the burst query rate limit
        time.sleep(10)
        self._test_rate_limiting(2, machine)

    def test_metadata_proxy_base_and_burst_rate_limiting(self):
        self.conf.set_override('base_query_rate_limit', 3,
                               'metadata_rate_limiting')
        self.conf.set_override('base_window_duration', 60,
                               'metadata_rate_limiting')
        self.conf.set_override('burst_query_rate_limit', 2,
                               'metadata_rate_limiting')
        self.conf.set_override('burst_window_duration', 5,
                               'metadata_rate_limiting')
        machine, _, _ = self._set_up_for_rate_limiting_test()

        # Since the number of metadata requests don't exceed the base or the
        # burst query rate limit, all of them should get "OK" response
        self._test_rate_limiting(2, machine, exceed=False)

        # Wait for haproxy to reset the burst window and then test it returns
        # "Too Many Requests" after exceeding the base query rate limit
        time.sleep(10)
        self._test_rate_limiting(1, machine)

    def test_metadata_proxy_rate_limiting_invalid_ip_versions(self):
        self.conf.set_override('base_query_rate_limit', 2,
                               'metadata_rate_limiting')
        self.conf.set_override('ip_versions', [4, 6],
                               'metadata_rate_limiting')
        machine, _, _ = self._set_up_for_rate_limiting_test()
        # Since we are passing an invalid ip_versions configuration, rate
        # limiting will not be configuerd and more than 2 requests should
        # succeed
        self._test_rate_limiting(3, machine, exceed=False)


class UnprivilegedUserMetadataL3AgentTestCase(MetadataL3AgentTestCase):
    """Test metadata proxy with least privileged user.

    The least privileged user has uid=65534 and is commonly named 'nobody' but
    not always, that's why we use its uid.
    """

    SOCKET_MODE = 0o664

    def setUp(self):
        super().setUp()
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
        super().setUp()
        self.agent.conf.set_override('metadata_proxy_user', '65534')
        self.agent.conf.set_override('metadata_proxy_group', '65534')

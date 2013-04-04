# vim: tabstop=4 shiftwidth=4 softtabstop=4

#    Copyright 2011 OpenStack Foundation
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

import os

import mock

from quantum.common import utils
from quantum.rootwrap import filters
from quantum.rootwrap import wrapper
from quantum.tests import base


class RootwrapTestCase(base.BaseTestCase):

    def setUp(self):
        super(RootwrapTestCase, self).setUp()
        self.filters = [
            filters.RegExpFilter("/bin/ls", "root", 'ls', '/[a-z]+'),
            filters.CommandFilter("/usr/bin/foo_bar_not_exist", "root"),
            filters.RegExpFilter("/bin/cat", "root", 'cat', '/[a-z]+'),
            filters.CommandFilter("/nonexistant/cat", "root"),
            filters.CommandFilter("/bin/cat", "root")]  # Keep this one last

    def tearDown(self):
        super(RootwrapTestCase, self).tearDown()

    def test_RegExpFilter_match(self):
        usercmd = ["ls", "/root"]
        filtermatch = wrapper.match_filter(self.filters, usercmd)
        self.assertFalse(filtermatch is None)
        self.assertEqual(filtermatch.get_command(usercmd),
                         ["/bin/ls", "/root"])

    def test_RegExpFilter_reject(self):
        usercmd = ["ls", "root"]
        filtermatch = wrapper.match_filter(self.filters, usercmd)
        self.assertTrue(filtermatch is None)

    def test_missing_command(self):
        valid_but_missing = ["foo_bar_not_exist"]
        invalid = ["foo_bar_not_exist_and_not_matched"]
        filtermatch = wrapper.match_filter(self.filters, valid_but_missing)
        self.assertTrue(filtermatch is not None)
        filtermatch = wrapper.match_filter(self.filters, invalid)
        self.assertTrue(filtermatch is None)

    def test_DnsmasqFilter(self):
        usercmd = ['QUANTUM_RELAY_SOCKET_PATH=A', 'QUANTUM_NETWORK_ID=foobar',
                   'dnsmasq', 'foo']
        f = filters.DnsmasqFilter("/usr/bin/dnsmasq", "root")
        self.assertTrue(f.match(usercmd))
        self.assertEqual(f.get_command(usercmd), ['/usr/bin/dnsmasq', 'foo'])
        env = f.get_environment(usercmd)
        self.assertEqual(env.get('QUANTUM_RELAY_SOCKET_PATH'), 'A')
        self.assertEqual(env.get('QUANTUM_NETWORK_ID'), 'foobar')

    def test_DnsmasqNetnsFilter(self):
        usercmd = ['QUANTUM_RELAY_SOCKET_PATH=A', 'QUANTUM_NETWORK_ID=foobar',
                   'ip', 'netns', 'exec', 'foo', 'dnsmasq', 'foo']
        f = filters.DnsmasqNetnsFilter("/sbin/ip", "root")
        self.assertTrue(f.match(usercmd))
        self.assertEqual(f.get_command(usercmd), ['/sbin/ip', 'netns', 'exec',
                                                  'foo', 'dnsmasq', 'foo'])
        env = f.get_environment(usercmd)
        self.assertEqual(env.get('QUANTUM_RELAY_SOCKET_PATH'), 'A')
        self.assertEqual(env.get('QUANTUM_NETWORK_ID'), 'foobar')

    def test_KillFilter(self):
        p = utils.subprocess_popen(["/bin/sleep", "5"])
        f = filters.KillFilter("root", "/bin/sleep", "-9", "-HUP")
        f2 = filters.KillFilter("root", "/usr/bin/sleep", "-9", "-HUP")
        usercmd = ['kill', '-ALRM', p.pid]
        # Incorrect signal should fail
        self.assertFalse(f.match(usercmd) or f2.match(usercmd))
        usercmd = ['kill', p.pid]
        # Providing no signal should fail
        self.assertFalse(f.match(usercmd) or f2.match(usercmd))
        # Providing matching signal should be allowed
        usercmd = ['kill', '-9', p.pid]
        self.assertTrue(f.match(usercmd) or f2.match(usercmd))

        f = filters.KillFilter("root", "/bin/sleep")
        f2 = filters.KillFilter("root", "/usr/bin/sleep")
        usercmd = ['kill', os.getpid()]
        # Our own PID does not match /bin/sleep, so it should fail
        self.assertFalse(f.match(usercmd) or f2.match(usercmd))
        usercmd = ['kill', 999999]
        # Nonexistant PID should fail
        self.assertFalse(f.match(usercmd) or f2.match(usercmd))
        usercmd = ['kill', p.pid]
        # Providing no signal should work
        self.assertTrue(f.match(usercmd) or f2.match(usercmd))

    def test_KillFilter_no_raise(self):
        """Makes sure ValueError from bug 926412 is gone"""
        f = filters.KillFilter("root", "")
        # Providing anything other than kill should be False
        usercmd = ['notkill', 999999]
        self.assertFalse(f.match(usercmd))
        # Providing something that is not a pid should be False
        usercmd = ['kill', 'notapid']
        self.assertFalse(f.match(usercmd))

    def test_KillFilter_deleted_exe(self):
        """Makes sure deleted exe's are killed correctly"""
        # See bug #1073768.
        with mock.patch('os.readlink') as mock_readlink:
            mock_readlink.return_value = '/bin/commandddddd (deleted)'
            f = filters.KillFilter("root", "/bin/commandddddd")
            usercmd = ['kill', 1234]
            self.assertTrue(f.match(usercmd))
            mock_readlink.assert_called_once_with("/proc/1234/exe")

    def test_ReadFileFilter(self):
        goodfn = '/good/file.name'
        f = filters.ReadFileFilter(goodfn)
        usercmd = ['cat', '/bad/file']
        self.assertFalse(f.match(['cat', '/bad/file']))
        usercmd = ['cat', goodfn]
        self.assertEqual(f.get_command(usercmd), ['/bin/cat', goodfn])
        self.assertTrue(f.match(usercmd))

    def test_IpFilter_non_netns(self):
        f = filters.IpFilter('/sbin/ip', 'root')
        self.assertTrue(f.match(['ip', 'link', 'list']))

    def _test_IpFilter_netns_helper(self, action):
        f = filters.IpFilter('/sbin/ip', 'root')
        self.assertTrue(f.match(['ip', 'link', action]))

    def test_IpFilter_netns_add(self):
        self._test_IpFilter_netns_helper('add')

    def test_IpFilter_netns_delete(self):
        self._test_IpFilter_netns_helper('delete')

    def test_IpFilter_netns_list(self):
        self._test_IpFilter_netns_helper('list')

    def test_IpNetnsExecFilter_match(self):
        f = filters.IpNetnsExecFilter('/sbin/ip', 'root')
        self.assertTrue(
            f.match(['ip', 'netns', 'exec', 'foo', 'ip', 'link', 'list']))

    def test_IpNetnsExecFilter_nomatch(self):
        f = filters.IpNetnsExecFilter('/sbin/ip', 'root')
        self.assertFalse(f.match(['ip', 'link', 'list']))

    def test_match_filter_recurses_exec_command_filter_matches(self):
        filter_list = [filters.IpNetnsExecFilter('/sbin/ip', 'root'),
                       filters.IpFilter('/sbin/ip', 'root')]
        args = ['ip', 'netns', 'exec', 'foo', 'ip', 'link', 'list']

        self.assertIsNotNone(wrapper.match_filter(filter_list, args))

    def test_match_filter_recurses_exec_command_filter_does_not_match(self):
        filter_list = [filters.IpNetnsExecFilter('/sbin/ip', 'root'),
                       filters.IpFilter('/sbin/ip', 'root')]
        args = ['ip', 'netns', 'exec', 'foo', 'ip', 'netns', 'exec', 'bar',
                'ip', 'link', 'list']

        self.assertIsNone(wrapper.match_filter(filter_list, args))

    def test_skips(self):
        # Check that all filters are skipped and that the last matches
        usercmd = ["cat", "/"]
        filtermatch = wrapper.match_filter(self.filters, usercmd)
        self.assertTrue(filtermatch is self.filters[-1])

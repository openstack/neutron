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

import ConfigParser
import logging
import logging.handlers
import os
import subprocess
import uuid

import fixtures

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
            filters.CommandFilter("/nonexistent/cat", "root"),
            filters.CommandFilter("/bin/cat", "root")  # Keep this one last
        ]

    def test_RegExpFilter_match(self):
        usercmd = ["ls", "/root"]
        filtermatch = wrapper.match_filter(self.filters, usercmd)
        self.assertFalse(filtermatch is None)
        self.assertEqual(filtermatch.get_command(usercmd),
                         ["/bin/ls", "/root"])

    def test_RegExpFilter_reject(self):
        usercmd = ["ls", "root"]
        self.assertRaises(wrapper.NoFilterMatched,
                          wrapper.match_filter, self.filters, usercmd)

    def test_missing_command(self):
        valid_but_missing = ["foo_bar_not_exist"]
        invalid = ["foo_bar_not_exist_and_not_matched"]
        self.assertRaises(wrapper.FilterMatchNotExecutable,
                          wrapper.match_filter,
                          self.filters, valid_but_missing)
        self.assertRaises(wrapper.NoFilterMatched,
                          wrapper.match_filter, self.filters, invalid)

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
        if not os.path.exists("/proc/%d" % os.getpid()):
            self.skipTest("Test requires /proc filesystem (procfs)")
        p = subprocess.Popen(["cat"], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        try:
            f = filters.KillFilter("root", "/bin/cat", "-9", "-HUP")
            f2 = filters.KillFilter("root", "/usr/bin/cat", "-9", "-HUP")
            usercmd = ['kill', '-ALRM', p.pid]
            # Incorrect signal should fail
            self.assertFalse(f.match(usercmd) or f2.match(usercmd))
            usercmd = ['kill', p.pid]
            # Providing no signal should fail
            self.assertFalse(f.match(usercmd) or f2.match(usercmd))
            # Providing matching signal should be allowed
            usercmd = ['kill', '-9', p.pid]
            self.assertTrue(f.match(usercmd) or f2.match(usercmd))

            f = filters.KillFilter("root", "/bin/cat")
            f2 = filters.KillFilter("root", "/usr/bin/cat")
            usercmd = ['kill', os.getpid()]
            # Our own PID does not match /bin/sleep, so it should fail
            self.assertFalse(f.match(usercmd) or f2.match(usercmd))
            usercmd = ['kill', 999999]
            # Nonexistent PID should fail
            self.assertFalse(f.match(usercmd) or f2.match(usercmd))
            usercmd = ['kill', p.pid]
            # Providing no signal should work
            self.assertTrue(f.match(usercmd) or f2.match(usercmd))
        finally:
            # Terminate the "cat" process and wait for it to finish
            p.terminate()
            p.wait()

    def test_KillFilter_no_raise(self):
        """Makes sure ValueError from bug 926412 is gone."""
        f = filters.KillFilter("root", "")
        # Providing anything other than kill should be False
        usercmd = ['notkill', 999999]
        self.assertFalse(f.match(usercmd))
        # Providing something that is not a pid should be False
        usercmd = ['kill', 'notapid']
        self.assertFalse(f.match(usercmd))

    def test_KillFilter_deleted_exe(self):
        """Makes sure deleted exe's are killed correctly."""
        # See bug #967931.
        def fake_readlink(blah):
            return '/bin/commandddddd (deleted)'

        f = filters.KillFilter("root", "/bin/commandddddd")
        usercmd = ['kill', 1234]
        # Providing no signal should work
        self.stubs.Set(os, 'readlink', fake_readlink)
        self.assertTrue(f.match(usercmd))

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

        self.assertRaises(wrapper.NoFilterMatched,
                          wrapper.match_filter, filter_list, args)

    def test_exec_dirs_search(self):
        # This test supposes you have /bin/cat or /usr/bin/cat locally
        f = filters.CommandFilter("cat", "root")
        usercmd = ['cat', '/f']
        self.assertTrue(f.match(usercmd))
        self.assertTrue(f.get_command(usercmd,
                                      exec_dirs=['/bin', '/usr/bin'])
                        in (['/bin/cat', '/f'], ['/usr/bin/cat', '/f']))

    def test_skips(self):
        # Check that all filters are skipped and that the last matches
        usercmd = ["cat", "/"]
        filtermatch = wrapper.match_filter(self.filters, usercmd)
        self.assertTrue(filtermatch is self.filters[-1])

    def test_RootwrapConfig(self):
        raw = ConfigParser.RawConfigParser()

        # Empty config should raise ConfigParser.Error
        self.assertRaises(ConfigParser.Error, wrapper.RootwrapConfig, raw)

        # Check default values
        raw.set('DEFAULT', 'filters_path', '/a,/b')
        config = wrapper.RootwrapConfig(raw)
        self.assertEqual(config.filters_path, ['/a', '/b'])
        self.assertEqual(config.exec_dirs, os.environ["PATH"].split(':'))
        self.assertFalse(config.use_syslog)
        self.assertEqual(config.syslog_log_facility,
                         logging.handlers.SysLogHandler.LOG_SYSLOG)
        self.assertEqual(config.syslog_log_level, logging.ERROR)

        # Check general values
        raw.set('DEFAULT', 'exec_dirs', '/a,/x')
        config = wrapper.RootwrapConfig(raw)
        self.assertEqual(config.exec_dirs, ['/a', '/x'])

        raw.set('DEFAULT', 'use_syslog', 'oui')
        self.assertRaises(ValueError, wrapper.RootwrapConfig, raw)
        raw.set('DEFAULT', 'use_syslog', 'true')
        config = wrapper.RootwrapConfig(raw)
        self.assertTrue(config.use_syslog)

        raw.set('DEFAULT', 'syslog_log_facility', 'moo')
        self.assertRaises(ValueError, wrapper.RootwrapConfig, raw)
        raw.set('DEFAULT', 'syslog_log_facility', 'local0')
        config = wrapper.RootwrapConfig(raw)
        self.assertEqual(config.syslog_log_facility,
                         logging.handlers.SysLogHandler.LOG_LOCAL0)
        raw.set('DEFAULT', 'syslog_log_facility', 'LOG_AUTH')
        config = wrapper.RootwrapConfig(raw)
        self.assertEqual(config.syslog_log_facility,
                         logging.handlers.SysLogHandler.LOG_AUTH)

        raw.set('DEFAULT', 'syslog_log_level', 'bar')
        self.assertRaises(ValueError, wrapper.RootwrapConfig, raw)
        raw.set('DEFAULT', 'syslog_log_level', 'INFO')
        config = wrapper.RootwrapConfig(raw)
        self.assertEqual(config.syslog_log_level, logging.INFO)


class PathFilterTestCase(base.BaseTestCase):
    def setUp(self):
        super(PathFilterTestCase, self).setUp()

        tmpdir = fixtures.TempDir('/tmp')
        self.useFixture(tmpdir)

        self.f = filters.PathFilter('/bin/chown', 'root', 'nova', tmpdir.path)

        gen_name = lambda: str(uuid.uuid4())

        self.SIMPLE_FILE_WITHIN_DIR = os.path.join(tmpdir.path, 'some')
        self.SIMPLE_FILE_OUTSIDE_DIR = os.path.join('/tmp', 'some')
        self.TRAVERSAL_WITHIN_DIR = os.path.join(tmpdir.path, 'a', '..',
                                                 'some')
        self.TRAVERSAL_OUTSIDE_DIR = os.path.join(tmpdir.path, '..', 'some')

        self.TRAVERSAL_SYMLINK_WITHIN_DIR = os.path.join(tmpdir.path,
                                                         gen_name())
        os.symlink(os.path.join(tmpdir.path, 'a', '..', 'a'),
                   self.TRAVERSAL_SYMLINK_WITHIN_DIR)

        self.TRAVERSAL_SYMLINK_OUTSIDE_DIR = os.path.join(tmpdir.path,
                                                          gen_name())
        os.symlink(os.path.join(tmpdir.path, 'a', '..', '..', '..', 'etc'),
                   self.TRAVERSAL_SYMLINK_OUTSIDE_DIR)

        self.SYMLINK_WITHIN_DIR = os.path.join(tmpdir.path, gen_name())
        os.symlink(os.path.join(tmpdir.path, 'a'), self.SYMLINK_WITHIN_DIR)

        self.SYMLINK_OUTSIDE_DIR = os.path.join(tmpdir.path, gen_name())
        os.symlink(os.path.join('/tmp', 'some_file'), self.SYMLINK_OUTSIDE_DIR)

    def test_argument_pass_constraint(self):
        f = filters.PathFilter('/bin/chown', 'root', 'pass', 'pass')

        args = ['chown', 'something', self.SIMPLE_FILE_OUTSIDE_DIR]
        self.assertTrue(f.match(args))

    def test_argument_equality_constraint(self):
        f = filters.PathFilter('/bin/chown', 'root', 'nova', '/tmp/spam/eggs')

        args = ['chown', 'nova', '/tmp/spam/eggs']
        self.assertTrue(f.match(args))

        args = ['chown', 'quantum', '/tmp/spam/eggs']
        self.assertFalse(f.match(args))

    def test_wrong_arguments_number(self):
        args = ['chown', '-c', 'nova', self.SIMPLE_FILE_WITHIN_DIR]
        self.assertFalse(self.f.match(args))

    def test_wrong_exec_command(self):
        args = ['wrong_exec', self.SIMPLE_FILE_WITHIN_DIR]
        self.assertFalse(self.f.match(args))

    def test_match(self):
        args = ['chown', 'nova', self.SIMPLE_FILE_WITHIN_DIR]
        self.assertTrue(self.f.match(args))

    def test_match_traversal(self):
        args = ['chown', 'nova', self.TRAVERSAL_WITHIN_DIR]
        self.assertTrue(self.f.match(args))

    def test_match_symlink(self):
        args = ['chown', 'nova', self.SYMLINK_WITHIN_DIR]
        self.assertTrue(self.f.match(args))

    def test_match_traversal_symlink(self):
        args = ['chown', 'nova', self.TRAVERSAL_SYMLINK_WITHIN_DIR]
        self.assertTrue(self.f.match(args))

    def test_reject(self):
        args = ['chown', 'nova', self.SIMPLE_FILE_OUTSIDE_DIR]
        self.assertFalse(self.f.match(args))

    def test_reject_traversal(self):
        args = ['chown', 'nova', self.TRAVERSAL_OUTSIDE_DIR]
        self.assertFalse(self.f.match(args))

    def test_reject_symlink(self):
        args = ['chown', 'nova', self.SYMLINK_OUTSIDE_DIR]
        self.assertFalse(self.f.match(args))

    def test_reject_traversal_symlink(self):
        args = ['chown', 'nova', self.TRAVERSAL_SYMLINK_OUTSIDE_DIR]
        self.assertFalse(self.f.match(args))

    def test_get_command(self):
        args = ['chown', 'nova', self.SIMPLE_FILE_WITHIN_DIR]
        expected = ['/bin/chown', 'nova', self.SIMPLE_FILE_WITHIN_DIR]

        self.assertEqual(expected, self.f.get_command(args))

    def test_get_command_traversal(self):
        args = ['chown', 'nova', self.TRAVERSAL_WITHIN_DIR]
        expected = ['/bin/chown', 'nova',
                    os.path.realpath(self.TRAVERSAL_WITHIN_DIR)]

        self.assertEqual(expected, self.f.get_command(args))

    def test_get_command_symlink(self):
        args = ['chown', 'nova', self.SYMLINK_WITHIN_DIR]
        expected = ['/bin/chown', 'nova',
                    os.path.realpath(self.SYMLINK_WITHIN_DIR)]

        self.assertEqual(expected, self.f.get_command(args))

    def test_get_command_traversal_symlink(self):
        args = ['chown', 'nova', self.TRAVERSAL_SYMLINK_WITHIN_DIR]
        expected = ['/bin/chown', 'nova',
                    os.path.realpath(self.TRAVERSAL_SYMLINK_WITHIN_DIR)]

        self.assertEqual(expected, self.f.get_command(args))

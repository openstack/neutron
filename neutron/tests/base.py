# Copyright 2010-2011 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Base test cases for all neutron tests.
"""

import abc
import contextlib
import functools
import inspect
import logging
import os
import os.path
import queue
import threading
from unittest import mock
import warnings

import eventlet.timeout
import fixtures
from neutron_lib.callbacks import manager as registry_manager
from neutron_lib.db import api as db_api
from neutron_lib import fixture
from neutron_lib.tests import tools as lib_test_tools
from neutron_lib.tests.unit import fake_notifier
from oslo_concurrency.fixture import lockutils
from oslo_config import cfg
from oslo_db import exception as db_exceptions
from oslo_db import options as db_options
from oslo_utils import excutils
from oslo_utils import fileutils
from oslo_utils import strutils
from oslotest import base
from osprofiler import profiler
from sqlalchemy import exc as sqlalchemy_exc
import testtools
from testtools import content

from neutron._i18n import _
from neutron.agent.linux import external_process
from neutron.api.rpc.callbacks.consumer import registry as rpc_consumer_reg
from neutron.api.rpc.callbacks.producer import registry as rpc_producer_reg
from neutron.common import config
from neutron.conf.agent import common as agent_config
from neutron.db import agentschedulers_db
from neutron import manager
from neutron import policy
from neutron.quota import resource_registry
from neutron.tests import post_mortem_debug


CONF = cfg.CONF
CONF.import_opt('state_path', 'neutron.conf.common')

ROOTDIR = os.path.dirname(__file__)
ETCDIR = os.path.join(ROOTDIR, 'etc')

SUDO_CMD = 'sudo -n'

TESTCASE_RETRIES = 3


def etcdir(*p):
    return os.path.join(ETCDIR, *p)


def fake_use_fatal_exceptions(*args):
    return True


def bool_from_env(key, strict=False, default=False):
    value = os.environ.get(key)
    return strutils.bool_from_string(value, strict=strict, default=default)


def setup_test_logging(config_opts, log_dir, log_file_path_template):
    # Have each test log into its own log file
    config_opts.set_override('debug', True)
    fileutils.ensure_tree(log_dir, mode=0o755)
    log_file = sanitize_log_path(
        os.path.join(log_dir, log_file_path_template))
    config_opts.set_override('log_file', log_file)
    config.setup_logging()


def sanitize_log_path(path):
    # Sanitize the string so that its log path is shell friendly
    replace_map = {' ': '-', '(': '_', ')': '_'}
    for s, r in replace_map.items():
        path = path.replace(s, r)
    return path


def unstable_test(reason):
    def decor(f):
        @functools.wraps(f)
        def inner(self, *args, **kwargs):
            try:
                return f(self, *args, **kwargs)
            except Exception as e:
                msg = ("%s was marked as unstable because of %s, "
                       "failure was: %s") % (self.id(), reason, e)
                raise self.skipTest(msg)
        return inner
    return decor


def skip_if_timeout(reason):
    def decor(f):
        @functools.wraps(f)
        def inner(self, *args, **kwargs):
            try:
                return f(self, *args, **kwargs)
            except fixtures.TimeoutException:
                msg = ("Timeout raised for test %s, skipping it "
                       "because of: %s") % (self.id(), reason)
                raise self.skipTest(msg)
            except (sqlalchemy_exc.InterfaceError,
                    db_exceptions.DBConnectionError):
                # In case of db tests very often TimeoutException is reason of
                # some sqlalchemy InterfaceError exception and that is final
                # raised exception which needs to be handled
                msg = ("DB connection broken in test %s. It is very likely "
                       "that this happend because of test timeout. "
                       "Skipping test because of: %s") % (self.id(), reason)
                raise self.skipTest(msg)
        return inner
    return decor


def set_timeout(timeout):
    """Timeout decorator for test methods.

    Use this decorator for tests that are expected to pass in very specific
    amount of time, not common for all other tests.
    It can have either big or small value.
    """
    def decor(f):
        @functools.wraps(f)
        def inner(self, *args, **kwargs):
            self.useFixture(fixtures.Timeout(timeout, gentle=True))
            return f(self, *args, **kwargs)
        return inner
    return decor


def get_rootwrap_cmd():
    return os.environ.get('OS_ROOTWRAP_CMD', SUDO_CMD)


def get_rootwrap_daemon_cmd():
    return os.environ.get('OS_ROOTWRAP_DAEMON_CMD')


class AttributeDict(dict):

    """Provide attribute access (dict.key) to dictionary values."""

    def __getattr__(self, name):
        """Allow attribute access for all keys in the dict."""
        if name in self:
            return self[name]
        raise AttributeError(_("Unknown attribute '%s'.") % name)


def _catch_timeout(f):
    @functools.wraps(f)
    def func(self, *args, **kwargs):
        for idx in range(1, TESTCASE_RETRIES + 1):
            try:
                return f(self, *args, **kwargs)
            except eventlet.Timeout as e:
                self.fail('Execution of this test timed out: %s' % e)
            # NOTE(ralonsoh): exception catch added due to the constant
            # occurrences of this exception during FT and UT execution.
            # This is due to [1]. Once the sync decorators are removed or the
            # privsep ones are decorated by those ones (swap decorator
            # declarations) this catch can be remove.
            # [1] https://review.opendev.org/#/c/631275/
            except fixtures.TimeoutException:
                if idx < TESTCASE_RETRIES:
                    msg = ('"fixtures.TimeoutException" during test case '
                           'execution no %s; test case re-executed' % idx)
                    self.addDetail('DietTestCase',
                                   content.text_content(msg))
                    self._set_timeout()
                else:
                    self.fail('Execution of this test timed out')
    return func


class _CatchTimeoutMetaclass(abc.ABCMeta):
    def __init__(cls, name, bases, dct):
        super(_CatchTimeoutMetaclass, cls).__init__(name, bases, dct)
        for name, method in inspect.getmembers(
                # NOTE(ihrachys): we should use isroutine because it will catch
                # both unbound methods (python2) and functions (python3)
                cls, predicate=inspect.isroutine):
            if name.startswith('test_'):
                setattr(cls, name, _catch_timeout(method))


# Test worker cannot survive eventlet's Timeout exception, which effectively
# kills the whole worker, with all test cases scheduled to it. This metaclass
# makes all test cases convert Timeout exceptions into unittest friendly
# failure mode (self.fail).
class DietTestCase(base.BaseTestCase, metaclass=_CatchTimeoutMetaclass):
    """Same great taste, less filling.

    BaseTestCase is responsible for doing lots of plugin-centric setup
    that not all tests require (or can tolerate).  This class provides
    only functionality that is common across all tests.
    """

    def setUp(self):
        super(DietTestCase, self).setUp()

        # NOTE(slaweq): Make deprecation warnings only happen once.
        warnings.simplefilter("once", DeprecationWarning)

        # NOTE(slaweq): Let's not display such warnings in tests as we know
        # that we have many places where policy enforcement depends on values
        # like is_admin or project_id and there can be a lot of such warnings
        # in the logs
        warnings.filterwarnings(
            'ignore', message=(
                'Policy enforcement is depending on the value of '))

        # Suppress some log messages during test runs, otherwise it may cause
        # issues with subunit parser when running on Python 3. It happened for
        # example for neutron-functional tests.
        # With this suppress of log levels DEBUG logs will not be captured by
        # stestr on pythonlogging stream and will not cause this parser issue.
        supress_logs = ['neutron', 'neutron_lib', 'stevedore', 'oslo_policy',
                        'oslo_concurrency', 'oslo_db', 'alembic', 'ovsdbapp']
        for supress_log in supress_logs:
            logger = logging.getLogger(supress_log)
            logger.setLevel(logging.ERROR)

        # FIXME(amuller): this must be called in the Neutron unit tests base
        # class. Moving this may cause non-deterministic failures. Bug #1489098
        # for more info.
        db_options.set_defaults(cfg.CONF, connection='sqlite://')

        # Configure this first to ensure pm debugging support for setUp()
        debugger = os.environ.get('OS_POST_MORTEM_DEBUGGER')
        if debugger:
            self.addOnException(post_mortem_debug.get_exception_handler(
                debugger))

        # Make sure we see all relevant deprecation warnings when running tests
        self.useFixture(fixture.WarningsFixture(module_re=['^neutron\\.']))

        self.useFixture(fixture.DBQueryHooksFixture())

        # NOTE(ihrachys): oslotest already sets stopall for cleanup, but it
        # does it using six.moves.mock (the library was moved into
        # unittest.mock in Python 3.4). So until we switch to six.moves.mock
        # everywhere in unit tests, we can't remove this setup. The base class
        # is used in 3party projects, so we would need to switch all of them to
        # six before removing the cleanup callback from here.
        self.addCleanup(mock.patch.stopall)

        self.useFixture(fixture.DBResourceExtendFixture())

        self.addOnException(self.check_for_systemexit)
        self.orig_pid = os.getpid()

        lib_test_tools.reset_random_seed()

    def addOnException(self, handler):

        def safe_handler(*args, **kwargs):
            try:
                return handler(*args, **kwargs)
            except Exception:
                with excutils.save_and_reraise_exception(reraise=False) as ctx:
                    self.addDetail('failure in exception handler %s' % handler,
                                   testtools.content.TracebackContent(
                                       (ctx.type_, ctx.value, ctx.tb), self))

        return super(DietTestCase, self).addOnException(safe_handler)

    def check_for_systemexit(self, exc_info):
        if isinstance(exc_info[1], SystemExit):
            if os.getpid() != self.orig_pid:
                # Subprocess - let it just exit
                raise
            # This makes sys.exit(0) still a failure
            self.force_failure = True

    @contextlib.contextmanager
    def assert_max_execution_time(self, max_execution_time=5):
        with eventlet.Timeout(max_execution_time, False):
            yield
            return
        self.fail('Execution of this test timed out')

    def assertOrderedEqual(self, expected, actual):
        expect_val = self.sort_dict_lists(expected)
        actual_val = self.sort_dict_lists(actual)
        self.assertEqual(expect_val, actual_val)

    def sort_dict_lists(self, dic):
        for key, value in dic.items():
            if isinstance(value, list):
                dic[key] = sorted(value)
            elif isinstance(value, dict):
                dic[key] = self.sort_dict_lists(value)
        return dic

    def assertDictSupersetOf(self, expected_subset, actual_superset):
        """Checks that actual dict contains the expected dict.

        After checking that the arguments are of the right type, this checks
        that each item in expected_subset is in, and matches, what is in
        actual_superset. Separate tests are done, so that detailed info can
        be reported upon failure.
        """
        if not isinstance(expected_subset, dict):
            self.fail("expected_subset (%s) is not an instance of dict" %
                      type(expected_subset))
        if not isinstance(actual_superset, dict):
            self.fail("actual_superset (%s) is not an instance of dict" %
                      type(actual_superset))
        for k, v in expected_subset.items():
            self.assertIn(k, actual_superset)
            self.assertEqual(v, actual_superset[k],
                             "Key %(key)s expected: %(exp)r, actual %(act)r" %
                             {'key': k, 'exp': v, 'act': actual_superset[k]})


class ProcessMonitorFixture(fixtures.Fixture):
    """Test fixture to capture and cleanup any spawn process monitor."""

    def _setUp(self):
        self.old_callable = (
            external_process.ProcessMonitor._spawn_checking_thread)
        p = mock.patch("neutron.agent.linux.external_process.ProcessMonitor."
                       "_spawn_checking_thread",
                       new=lambda x: self.record_calls(x))
        p.start()
        self.instances = []
        self.addCleanup(self.stop)

    def stop(self):
        for instance in self.instances:
            instance.stop()

    def record_calls(self, instance):
        self.old_callable(instance)
        self.instances.append(instance)


class BaseTestCase(DietTestCase):

    @staticmethod
    def config_parse(conf=None, args=None):
        """Create the default configurations."""
        if args is None:
            args = []
        args += ['--config-file', etcdir('neutron.conf')]
        if conf is None:
            config.init(args=args)
        else:
            conf(args)

    def setUp(self):
        super(BaseTestCase, self).setUp()

        self.useFixture(lockutils.ExternalLockFixture())
        self.useFixture(fixture.APIDefinitionFixture())

        cfg.CONF.set_override('state_path', self.get_default_temp_dir().path)

        self.addCleanup(CONF.reset)
        self.useFixture(ProcessMonitorFixture())

        self.useFixture(fixtures.MonkeyPatch(
            'neutron_lib.exceptions.NeutronException.use_fatal_exceptions',
            fake_use_fatal_exceptions))

        self.useFixture(fixtures.MonkeyPatch(
            'oslo_config.cfg.find_config_files',
            lambda project=None, prog=None, extension=None: []))

        self.useFixture(fixture.RPCFixture())

        self.setup_config()

        self._callback_manager = registry_manager.CallbacksManager()
        self.useFixture(fixture.CallbackRegistryFixture(
            callback_manager=self._callback_manager))
        # Give a private copy of the directory to each test.
        self.useFixture(fixture.PluginDirectoryFixture())

        policy.init(suppress_deprecation_warnings=True)
        self.addCleanup(policy.reset)
        self.addCleanup(resource_registry.unregister_all_resources)
        self.addCleanup(db_api.sqla_remove_all)
        self.addCleanup(rpc_consumer_reg.clear)
        self.addCleanup(rpc_producer_reg.clear)
        self.addCleanup(profiler.clean)

    def get_new_temp_dir(self):
        """Create a new temporary directory.

        :returns: fixtures.TempDir
        """
        return self.useFixture(fixtures.TempDir())

    def get_default_temp_dir(self):
        """Create a default temporary directory.

        Returns the same directory during the whole test case.

        :returns: fixtures.TempDir
        """
        if not hasattr(self, '_temp_dir'):
            self._temp_dir = self.get_new_temp_dir()
        return self._temp_dir

    def get_temp_file_path(self, filename, root=None):
        """Returns an absolute path for a temporary file.

        If root is None, the file is created in default temporary directory. It
        also creates the directory if it's not initialized yet.

        If root is not None, the file is created inside the directory passed as
        root= argument.

        :param filename: filename
        :type filename: string
        :param root: temporary directory to create a new file in
        :type root: fixtures.TempDir
        :returns: absolute file path string
        """
        root = root or self.get_default_temp_dir()
        return root.join(filename)

    def setup_config(self, args=None):
        """Tests that need a non-default config can override this method."""
        self.config_parse(args=args)

    def config(self, **kw):
        """Override some configuration values.

        The keyword arguments are the names of configuration options to
        override and their values.

        If a group argument is supplied, the overrides are applied to
        the specified configuration option group.

        All overrides are automatically cleared at the end of the current
        test by the fixtures cleanup process.
        """
        group = kw.pop('group', None)
        for k, v in kw.items():
            CONF.set_override(k, v, group)

    def setup_coreplugin(self, core_plugin=None, load_plugins=True):
        cp = PluginFixture(core_plugin)
        self.useFixture(cp)
        self.patched_dhcp_periodic = cp.patched_dhcp_periodic
        self.patched_default_svc_plugins = cp.patched_default_svc_plugins
        if load_plugins:
            manager.init()

    def setup_notification_driver(self, notification_driver=None):
        self.addCleanup(fake_notifier.reset)
        if notification_driver is None:
            notification_driver = [fake_notifier.__name__]
        cfg.CONF.set_override("notification_driver", notification_driver)

    def setup_rootwrap(self):
        agent_config.register_root_helper(cfg.CONF)
        self.config(group='AGENT',
                    root_helper=get_rootwrap_cmd())
        self.config(group='AGENT',
                    root_helper_daemon=get_rootwrap_daemon_cmd())

    def _simulate_concurrent_requests_process_and_raise(self, calls, args):
        self._simulate_concurrent_requests_process(calls, args,
                                                   raise_on_exception=True)

    def _simulate_concurrent_requests_process(self, calls, args,
                                              raise_on_exception=False):
        class SimpleThread(threading.Thread):
            def __init__(self, q):
                super(SimpleThread, self).__init__()
                self.q = q
                self.exception = None

            def run(self):
                try:
                    while not self.q.empty():
                        item = None
                        try:
                            item = self.q.get(False)
                            func, func_args = item[0], item[1]
                            func(*func_args)
                        except queue.Empty:
                            pass
                        finally:
                            if item:
                                self.q.task_done()
                except Exception as e:
                    self.exception = e

            def get_exception(self):
                return self.exception

        q = queue.Queue()
        for func, func_args in zip(calls, args):
            q.put_nowait((func, func_args))

        threads = []
        for z in range(len(calls)):
            t = SimpleThread(q)
            threads.append(t)
            t.start()
        q.join()

        threads_exceptions = []
        for t in threads:
            e = t.get_exception()
            if e:
                if raise_on_exception:
                    raise e
                else:
                    threads_exceptions.append(e)

        return threads_exceptions


class PluginFixture(fixtures.Fixture):

    def __init__(self, core_plugin=None):
        super(PluginFixture, self).__init__()
        self.core_plugin = core_plugin

    def _setUp(self):
        # Do not load default service plugins in the testing framework
        # as all the mocking involved can cause havoc.
        self.default_svc_plugins_p = mock.patch(
            'neutron.manager.NeutronManager._get_default_service_plugins')
        self.patched_default_svc_plugins = self.default_svc_plugins_p.start()
        self.dhcp_periodic_p = mock.patch(
            'neutron.db.agentschedulers_db.DhcpAgentSchedulerDbMixin.'
            'add_periodic_dhcp_agent_status_check')
        self.patched_dhcp_periodic = self.dhcp_periodic_p.start()
        self.agent_health_check_p = mock.patch(
            'neutron.db.agentschedulers_db.DhcpAgentSchedulerDbMixin.'
            'add_agent_status_check_worker')
        self.agent_health_check = self.agent_health_check_p.start()
        # Plugin cleanup should be triggered last so that
        # test-specific cleanup has a chance to release references.
        self.addCleanup(self.cleanup_core_plugin)
        if self.core_plugin is not None:
            cfg.CONF.set_override('core_plugin', self.core_plugin)

    def cleanup_core_plugin(self):
        """Ensure that the core plugin is deallocated."""
        nm = manager.NeutronManager
        if not nm.has_instance():
            return

        # TODO(marun) Fix plugins that do not properly initialize notifiers
        agentschedulers_db.AgentSchedulerDbMixin.agent_notifiers = {}

        nm.clear_instance()


class Timeout(fixtures.Fixture):
    """Setup per test timeouts.

    In order to avoid test deadlocks we support setting up a test
    timeout parameter read from the environment. In almost all
    cases where the timeout is reached this means a deadlock.

    A scaling factor allows extremely long tests to specify they
    need more time.
    """

    def __init__(self, timeout=None, scaling=1):
        super(Timeout, self).__init__()
        if timeout is None:
            timeout = os.environ.get('OS_TEST_TIMEOUT', 0)
        try:
            self.test_timeout = int(timeout)
        except ValueError:
            # If timeout value is invalid do not set a timeout.
            self.test_timeout = 0
        if scaling >= 1:
            self.test_timeout *= scaling
        else:
            raise ValueError('scaling value must be >= 1')

    def setUp(self):
        super(Timeout, self).setUp()
        if self.test_timeout > 0:
            self.useFixture(fixtures.Timeout(self.test_timeout, gentle=True))

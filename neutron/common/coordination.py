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

"""Coordination and locking utilities."""

import inspect

import decorator
from oslo_concurrency import lockutils
from oslo_log import log
from oslo_utils import timeutils

LOG = log.getLogger(__name__)


def synchronized(lock_name):
    """Synchronization decorator.

    :param str lock_name: Lock name.

    Decorating a method like so::

        @synchronized('mylock')
        def foo(self, *args):
           ...

    ensures that only one process will execute the foo method at a time.

    Different methods can share the same lock::

        @synchronized('mylock')
        def foo(self, *args):
           ...

        @synchronized('mylock')
        def bar(self, *args):
           ...

    This way only one of either foo or bar can be executing at a time.

    Lock name can be formatted using Python format string syntax::

        @synchronized('{f_name}-{resource.id}-{snap[name]}')
        def foo(self, resource, snap):
           ...

    Available field names are: decorated function parameters and
    `f_name` as a decorated function name.
    """

    @decorator.decorator
    def _synchronized(f, *a, **k):
        sig = inspect.signature(f).bind(*a, **k)
        sig.apply_defaults()
        call_args = sig.arguments
        call_args['f_name'] = f.__name__
        lock_format_name = lock_name.format(**call_args)
        t1 = timeutils.now()
        t2 = None
        try:
            with lockutils.lock(lock_format_name):
                t2 = timeutils.now()
                LOG.debug('Lock "%(name)s" acquired by "%(function)s" :: '
                          'waited %(wait_secs)0.3fs',
                          {'name': lock_format_name,
                           'function': f.__name__,
                           'wait_secs': (t2 - t1)})
                return f(*a, **k)
        finally:
            t3 = timeutils.now()
            if t2 is None:
                held_secs = "N/A"
            else:
                held_secs = "%0.3fs" % (t3 - t2)
            LOG.debug('Lock "%(name)s" released by "%(function)s" :: held '
                      '%(held_secs)s',
                      {'name': lock_format_name,
                       'function': f.__name__,
                       'held_secs': held_secs})

    return _synchronized

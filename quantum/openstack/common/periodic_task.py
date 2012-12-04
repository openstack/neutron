# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

from quantum.openstack.common.gettextutils import _
from quantum.openstack.common import log as logging

LOG = logging.getLogger(__name__)


def periodic_task(*args, **kwargs):
    """Decorator to indicate that a method is a periodic task.

    This decorator can be used in two ways:

        1. Without arguments '@periodic_task', this will be run on every tick
           of the periodic scheduler.

        2. With arguments, @periodic_task(ticks_between_runs=N), this will be
           run on every N ticks of the periodic scheduler.
    """
    def decorator(f):
        f._periodic_task = True
        f._ticks_between_runs = kwargs.pop('ticks_between_runs', 0)
        return f

    # NOTE(sirp): The `if` is necessary to allow the decorator to be used with
    # and without parens.
    #
    # In the 'with-parens' case (with kwargs present), this function needs to
    # return a decorator function since the interpreter will invoke it like:
    #
    #   periodic_task(*args, **kwargs)(f)
    #
    # In the 'without-parens' case, the original function will be passed
    # in as the first argument, like:
    #
    #   periodic_task(f)
    if kwargs:
        return decorator
    else:
        return decorator(args[0])


class _PeriodicTasksMeta(type):
    def __init__(cls, names, bases, dict_):
        """Metaclass that allows us to collect decorated periodic tasks."""
        super(_PeriodicTasksMeta, cls).__init__(names, bases, dict_)

        # NOTE(sirp): if the attribute is not present then we must be the base
        # class, so, go ahead and initialize it. If the attribute is present,
        # then we're a subclass so make a copy of it so we don't step on our
        # parent's toes.
        try:
            cls._periodic_tasks = cls._periodic_tasks[:]
        except AttributeError:
            cls._periodic_tasks = []

        try:
            cls._ticks_to_skip = cls._ticks_to_skip.copy()
        except AttributeError:
            cls._ticks_to_skip = {}

        # This uses __dict__ instead of
        # inspect.getmembers(cls, inspect.ismethod) so only the methods of the
        # current class are added when this class is scanned, and base classes
        # are not added redundantly.
        for value in cls.__dict__.values():
            if getattr(value, '_periodic_task', False):
                task = value
                name = task.__name__
                cls._periodic_tasks.append((name, task))
                cls._ticks_to_skip[name] = task._ticks_between_runs


class PeriodicTasks(object):
    __metaclass__ = _PeriodicTasksMeta

    def run_periodic_tasks(self, context, raise_on_error=False):
        """Tasks to be run at a periodic interval."""
        for task_name, task in self._periodic_tasks:
            full_task_name = '.'.join([self.__class__.__name__, task_name])

            ticks_to_skip = self._ticks_to_skip[task_name]
            if ticks_to_skip > 0:
                LOG.debug(_("Skipping %(full_task_name)s, %(ticks_to_skip)s"
                            " ticks left until next run"), locals())
                self._ticks_to_skip[task_name] -= 1
                continue

            self._ticks_to_skip[task_name] = task._ticks_between_runs
            LOG.debug(_("Running periodic task %(full_task_name)s"), locals())

            try:
                task(self, context)
            except Exception as e:
                if raise_on_error:
                    raise
                LOG.exception(_("Error during %(full_task_name)s: %(e)s"),
                              locals())

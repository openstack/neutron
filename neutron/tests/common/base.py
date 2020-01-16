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
#

import functools
import unittest

from neutron_lib import constants as n_const
import testtools.testcase

from neutron.common import utils
from neutron.tests import base
from neutron.tests import tools


def create_resource(prefix, creation_func, *args, **kwargs):
    """Create a new resource that does not already exist.

    If prefix isn't 'max_length' in size, a random suffix is concatenated to
    ensure it is random. Otherwise, 'prefix' is used as is.

    :param prefix: The prefix for a randomly generated name
    :param creation_func: A function taking the name of the resource
           to be created as it's first argument.  An error is assumed
           to indicate a name collision.
    :param *args *kwargs: These will be passed to the create function.
    """

    # Don't generate a random name if prefix is already full-length.
    if len(prefix) == n_const.DEVICE_NAME_MAX_LEN:
        return creation_func(prefix, *args, **kwargs)

    while True:
        name = utils.get_rand_name(
            max_length=n_const.DEVICE_NAME_MAX_LEN,
            prefix=prefix)
        try:
            return creation_func(name, *args, **kwargs)
        except RuntimeError:
            pass


def no_skip_on_missing_deps(wrapped):
    """Do not allow a method/test to skip on missing dependencies.

    This decorator raises an error if a skip is raised by wrapped method when
    OS_FAIL_ON_MISSING_DEPS is evaluated to True. This decorator should be used
    only for missing dependencies (including missing system requirements).
    """

    @functools.wraps(wrapped)
    def wrapper(*args, **kwargs):
        try:
            return wrapped(*args, **kwargs)
        except (testtools.TestCase.skipException, unittest.SkipTest) as e:
            if base.bool_from_env('OS_FAIL_ON_MISSING_DEPS'):
                tools.fail(
                    '%s cannot be skipped because OS_FAIL_ON_MISSING_DEPS '
                    'is enabled, skip reason: %s' % (wrapped.__name__, e))
            raise
    return wrapper

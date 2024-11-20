# Copyright 2013 Red Hat, Inc.
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

import functools
import traceback


def get_exception_handler(debugger_name):
    debugger = _get_debugger(debugger_name)
    return functools.partial(_exception_handler, debugger)


def _get_debugger(debugger_name):
    try:
        debugger = __import__(debugger_name)
    except ImportError:
        raise ValueError("can't import %s module as a post mortem debugger" %
                         debugger_name)
    if 'post_mortem' in dir(debugger):
        return debugger
    raise ValueError("%s is not a supported post mortem debugger" %
                     debugger_name)


def _exception_handler(debugger, exc_info):
    """Exception handler enabling post-mortem debugging.

    A class extending testtools.TestCase can add this handler in setUp():

        self.addOnException(post_mortem_debug.exception_handler)

    When an exception occurs, the user will be dropped into a debugger
    session in the execution environment of the failure.

    Frames associated with the testing framework are excluded so that
    the post-mortem session for an assertion failure will start at the
    assertion call (e.g. self.assertTrue) rather than the framework code
    that raises the failure exception (e.g. the assertTrue method).
    """
    tb = exc_info[2]
    ignored_traceback = get_ignored_traceback(tb)
    if ignored_traceback:
        tb = FilteredTraceback(tb, ignored_traceback)
    traceback.print_exception(exc_info[0], exc_info[1], tb)
    debugger.post_mortem(tb)


def get_ignored_traceback(tb):
    """Retrieve the first traceback of an ignored trailing chain.

    Given an initial traceback, find the first traceback of a trailing
    chain of tracebacks that should be ignored.  The criteria for
    whether a traceback should be ignored is whether its frame's
    globals include the __unittest marker variable. This criteria is
    culled from:

        unittest.TestResult._is_relevant_tb_level

    For example:

       tb.tb_next => tb0.tb_next => tb1.tb_next

    - If no tracebacks were to be ignored, None would be returned.
    - If only tb1 was to be ignored, tb1 would be returned.
    - If tb0 and tb1 were to be ignored, tb0 would be returned.
    - If either of only tb or only tb0 was to be ignored, None would
      be returned because neither tb or tb0 would be part of a
      trailing chain of ignored tracebacks.
    """
    # Turn the traceback chain into a list
    tb_list = []
    while tb:
        tb_list.append(tb)
        tb = tb.tb_next

    # Find all members of an ignored trailing chain
    ignored_tracebacks = []
    for tb in reversed(tb_list):
        if '__unittest' not in tb.tb_frame.f_globals:
            break
        ignored_tracebacks.append(tb)

    # Return the first member of the ignored trailing chain
    if ignored_tracebacks:
        return ignored_tracebacks[-1]


class FilteredTraceback:
    """Wraps a traceback to filter unwanted frames."""

    def __init__(self, tb, filtered_traceback):
        """Constructor.

        :param tb: The start of the traceback chain to filter.
        :param filtered_traceback: The first traceback of a trailing
               chain that is to be filtered.
        """
        self._tb = tb
        self.tb_lasti = self._tb.tb_lasti
        self.tb_lineno = self._tb.tb_lineno
        self.tb_frame = self._tb.tb_frame
        self._filtered_traceback = filtered_traceback

    @property
    def tb_next(self):
        tb_next = self._tb.tb_next
        if tb_next and tb_next != self._filtered_traceback:
            return FilteredTraceback(tb_next, self._filtered_traceback)

# Copyright (c) 2014 Red Hat, Inc.
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
import eventlet


def wait_until_true(predicate, timeout=60, sleep=1, exception=None):
    """
    Wait until callable predicate is evaluated as True

    :param predicate: Callable deciding whether waiting should continue.
    Best practice is to instantiate predicate with functools.partial()
    :param timeout: Timeout in seconds how long should function wait.
    :param sleep: Polling interval for results in seconds.
    :param exception: Exception class for eventlet.Timeout.
    (see doc for eventlet.Timeout for more information)
    """
    with eventlet.timeout.Timeout(timeout, exception):
        while not predicate():
            eventlet.sleep(sleep)


class Pinger(object):
    def __init__(self, testcase, timeout=1, max_attempts=1):
        self.testcase = testcase
        self._timeout = timeout
        self._max_attempts = max_attempts

    def _ping_destination(self, src_namespace, dest_address):
        src_namespace.netns.execute(['ping', '-c', self._max_attempts,
                                     '-W', self._timeout, dest_address])

    def assert_ping_from_ns(self, src_ns, dst_ip):
        try:
            self._ping_destination(src_ns, dst_ip)
        except RuntimeError:
            self.testcase.fail("destination ip %(dst_ip)s is not replying "
                               "to ping from namespace %(src_ns)s" %
                               {'src_ns': src_ns.namespace, 'dst_ip': dst_ip})

    def assert_no_ping_from_ns(self, src_ns, dst_ip):
        try:
            self._ping_destination(src_ns, dst_ip)
            self.testcase.fail("destination ip %(dst_ip)s is replying to ping"
                               "from namespace %(src_ns)s, but it shouldn't" %
                               {'src_ns': src_ns.namespace, 'dst_ip': dst_ip})
        except RuntimeError:
            pass

# Copyright 2013 NTT Corporation
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

import re

from testtools import helpers


class ExistsAllResponseHeaders(object):
    """
    Specific matcher to check the existence of Swift's response headers

    This matcher checks the existence of common headers for each HTTP method
    or the target, which means account, container or object.
    When checking the existence of 'specific' headers such as
    X-Account-Meta-* or X-Object-Manifest for example, those headers must be
    checked in each test code.
    """

    def __init__(self, target, method):
        """
        param: target Account/Container/Object
        param: method PUT/GET/HEAD/DELETE/COPY/POST
        """
        self.target = target
        self.method = method

    def match(self, actual):
        """
        param: actual HTTP response headers
        """
        # Check common headers for all HTTP methods
        if 'content-length' not in actual:
            return NonExistentHeader('content-length')
        if 'content-type' not in actual:
            return NonExistentHeader('content-type')
        if 'x-trans-id' not in actual:
            return NonExistentHeader('x-trans-id')
        if 'date' not in actual:
            return NonExistentHeader('date')

        # Check headers for a specific method or target
        if self.method == 'GET' or self.method == 'HEAD':
            if 'x-timestamp' not in actual:
                return NonExistentHeader('x-timestamp')
            if 'accept-ranges' not in actual:
                return NonExistentHeader('accept-ranges')
            if self.target == 'Account':
                if 'x-account-bytes-used' not in actual:
                    return NonExistentHeader('x-account-bytes-used')
                if 'x-account-container-count' not in actual:
                    return NonExistentHeader('x-account-container-count')
                if 'x-account-object-count' not in actual:
                    return NonExistentHeader('x-account-object-count')
            elif self.target == 'Container':
                if 'x-container-bytes-used' not in actual:
                    return NonExistentHeader('x-container-bytes-used')
                if 'x-container-object-count' not in actual:
                    return NonExistentHeader('x-container-object-count')
            elif self.target == 'Object':
                if 'etag' not in actual:
                    return NonExistentHeader('etag')
                if 'last-modified' not in actual:
                    return NonExistentHeader('last-modified')
        elif self.method == 'PUT':
            if self.target == 'Object':
                if 'etag' not in actual:
                    return NonExistentHeader('etag')
                if 'last-modified' not in actual:
                    return NonExistentHeader('last-modified')
        elif self.method == 'COPY':
            if self.target == 'Object':
                if 'etag' not in actual:
                    return NonExistentHeader('etag')
                if 'last-modified' not in actual:
                    return NonExistentHeader('last-modified')
                if 'x-copied-from' not in actual:
                    return NonExistentHeader('x-copied-from')
                if 'x-copied-from-last-modified' not in actual:
                    return NonExistentHeader('x-copied-from-last-modified')

        return None


class NonExistentHeader(object):
    """
    Informs an error message for end users in the case of missing a
    certain header in Swift's responses
    """

    def __init__(self, header):
        self.header = header

    def describe(self):
        return "%s header does not exist" % self.header

    def get_details(self):
        return {}


class AreAllWellFormatted(object):
    """
    Specific matcher to check the correctness of formats of values of Swift's
    response headers

    This matcher checks the format of values of response headers.
    When checking the format of values of 'specific' headers such as
    X-Account-Meta-* or X-Object-Manifest for example, those values must be
    checked in each test code.
    """

    def match(self, actual):
        for key, value in actual.iteritems():
            if key in ('content-length', 'x-account-bytes-used',
                       'x-account-container-count', 'x-account-object-count',
                       'x-container-bytes-used', 'x-container-object-count')\
                and not value.isdigit():
                return InvalidFormat(key, value)
            elif key in ('content-type', 'date', 'last-modified',
                         'x-copied-from-last-modified') and not value:
                return InvalidFormat(key, value)
            elif key == 'x-timestamp' and not re.match("^\d+\.?\d*\Z", value):
                return InvalidFormat(key, value)
            elif key == 'x-copied-from' and not re.match("\S+/\S+", value):
                return InvalidFormat(key, value)
            elif key == 'x-trans-id' and \
                not re.match("^tx[0-9a-f]{21}-[0-9a-f]{10}.*", value):
                return InvalidFormat(key, value)
            elif key == 'accept-ranges' and not value == 'bytes':
                return InvalidFormat(key, value)
            elif key == 'etag' and not value.isalnum():
                return InvalidFormat(key, value)
            elif key == 'transfer-encoding' and not value == 'chunked':
                return InvalidFormat(key, value)

        return None


class InvalidFormat(object):
    """
    Informs an error message for end users if a format of a certain header
    is invalid
    """

    def __init__(self, key, value):
        self.key = key
        self.value = value

    def describe(self):
        return "InvalidFormat (%s, %s)" % (self.key, self.value)

    def get_details(self):
        return {}


class MatchesDictExceptForKeys(object):
    """Matches two dictionaries. Verifies all items are equals except for those
    identified by a list of keys.
    """

    def __init__(self, expected, excluded_keys=None):
        self.expected = expected
        self.excluded_keys = excluded_keys if excluded_keys is not None else []

    def match(self, actual):
        filtered_expected = helpers.dict_subtract(self.expected,
                                                  self.excluded_keys)
        filtered_actual = helpers.dict_subtract(actual,
                                                self.excluded_keys)
        if filtered_actual != filtered_expected:
            return DictMismatch(filtered_expected, filtered_actual)


class DictMismatch(object):
    """Mismatch between two dicts describes deltas"""

    def __init__(self, expected, actual):
        self.expected = expected
        self.actual = actual
        self.intersect = set(self.expected) & set(self.actual)
        self.symmetric_diff = set(self.expected) ^ set(self.actual)

    def _format_dict(self, dict_to_format):
        # Ensure the error string dict is printed in a set order
        # NOTE(mtreinish): needed to ensure a deterministic error msg for
        # testing. Otherwise the error message will be dependent on the
        # dict ordering.
        dict_string = "{"
        for key in sorted(dict_to_format):
            dict_string += "'%s': %s, " % (key, dict_to_format[key])
        dict_string = dict_string[:-2] + '}'
        return dict_string

    def describe(self):
        msg = ""
        if self.symmetric_diff:
            only_expected = helpers.dict_subtract(self.expected, self.actual)
            only_actual = helpers.dict_subtract(self.actual, self.expected)
            if only_expected:
                msg += "Only in expected:\n  %s\n" % self._format_dict(
                    only_expected)
            if only_actual:
                msg += "Only in actual:\n  %s\n" % self._format_dict(
                    only_actual)
        diff_set = set(o for o in self.intersect if
                       self.expected[o] != self.actual[o])
        if diff_set:
            msg += "Differences:\n"
            for o in diff_set:
                msg += "  %s: expected %s, actual %s\n" % (
                    o, self.expected[o], self.actual[o])
        return msg

    def get_details(self):
        return {}

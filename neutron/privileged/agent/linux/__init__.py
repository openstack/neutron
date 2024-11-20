# Copyright 2020 Red Hat, Inc.
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

import ctypes
from ctypes import util as ctypes_util

from pyroute2 import netlink


_CDLL = None


def get_cdll():
    global _CDLL
    if not _CDLL:
        # NOTE(ralonsoh): from https://docs.python.org/3.6/library/
        # ctypes.html#ctypes.PyDLL: "Instances of this class behave like CDLL
        # instances, except that the Python GIL is not released during the
        # function call, and after the function execution the Python error
        # flag is checked."
        # Check https://bugs.launchpad.net/neutron/+bug/1870352
        _CDLL = ctypes.PyDLL(ctypes_util.find_library('c'), use_errno=True)
    return _CDLL


def make_serializable(value):
    """Make a pyroute2 object serializable

    This function converts 'netlink.nla_slot' object (key, value) in a list
    of two elements.
    """
    def _ensure_string(value):
        return value.decode() if isinstance(value, bytes) else value

    if isinstance(value, list):
        return [make_serializable(item) for item in value]
    if isinstance(value, netlink.nla_slot):
        return [_ensure_string(value[0]), make_serializable(value[1])]
    if isinstance(value, netlink.nla_base):
        return make_serializable(value.dump())
    if isinstance(value, dict):
        return {_ensure_string(key): make_serializable(data)
                for key, data in value.items()}
    if isinstance(value, tuple):
        return tuple(make_serializable(item) for item in value)
    return _ensure_string(value)

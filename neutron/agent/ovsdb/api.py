# Copyright (c) 2014 OpenStack Foundation
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

import collections
import uuid

from oslo_config import cfg
from oslo_utils import importutils

from neutron.conf.agent import ovsdb_api


ovsdb_api.register_ovsdb_api_opts()


def from_config(context, iface_name=None):
    """Return the configured OVSDB API implementation"""
    iface = importutils.import_module(
        ovsdb_api.interface_map[iface_name or cfg.CONF.OVS.ovsdb_interface])
    return iface.api_factory(context)


def val_to_py(val):
    """Convert a json ovsdb return value to native python object"""
    if isinstance(val, collections.Sequence) and len(val) == 2:
        if val[0] == "uuid":
            return uuid.UUID(val[1])
        elif val[0] == "set":
            return [val_to_py(x) for x in val[1]]
        elif val[0] == "map":
            return {val_to_py(x): val_to_py(y) for x, y in val[1]}
    return val


def py_to_val(pyval):
    """Convert python value to ovs-vsctl value argument"""
    if isinstance(pyval, bool):
        return 'true' if pyval is True else 'false'
    elif pyval == '':
        return '""'
    else:
        # NOTE(twilson) If a Command object, return its record_id as a value
        return getattr(pyval, "record_id", pyval)

# Copyright 2018 Red Hat, Inc.
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

import errno
import socket

from neutron_lib import constants as n_constants
import pyroute2
from pyroute2 import protocols as pyroute2_protocols

from neutron._i18n import _
from neutron import privileged
from neutron.privileged.agent.linux import ip_lib


_IP_VERSION_FAMILY_MAP = {n_constants.IP_VERSION_4: socket.AF_INET,
                          n_constants.IP_VERSION_6: socket.AF_INET6}


class TrafficControlClassNotFound(RuntimeError):
    message = _('Traffic control class %(classid)s not found in namespace '
                '%(namespace)s.')

    def __init__(self, message=None, classid=None, namespace=None):
        message = message or self.message % {
                'classid': classid, 'namespace': namespace}
        super(TrafficControlClassNotFound, self).__init__(message)


@privileged.default.entrypoint
def add_tc_qdisc(device, namespace=None, **kwargs):
    """Add TC qdisc"""
    index = ip_lib.get_link_id(device, namespace)
    try:
        with ip_lib.get_iproute(namespace) as ip:
            ip.tc('replace', index=index, **kwargs)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise ip_lib.NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def list_tc_qdiscs(device, namespace=None):
    """List all TC qdiscs of a device"""
    index = ip_lib.get_link_id(device, namespace)
    try:
        with ip_lib.get_iproute(namespace) as ip:
            return ip_lib.make_serializable(ip.get_qdiscs(index=index))
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise ip_lib.NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def delete_tc_qdisc(device, parent=None, kind=None, namespace=None,
                    raise_interface_not_found=True,
                    raise_qdisc_not_found=True):
    """Delete a TC qdisc of a device"""
    try:
        index = ip_lib.get_link_id(device, namespace)
        args = {}
        if parent:
            args['parent'] = parent
        if kind:
            args['kind'] = kind
        with ip_lib.get_iproute(namespace) as ip:
            ip.tc('del', index=index, **args)
    except ip_lib.NetworkInterfaceNotFound:
        if raise_interface_not_found:
            raise
    except pyroute2.NetlinkError as e:
        # NOTE(ralonsoh): tc delete will raise a NetlinkError exception with
        # code (22, 'Invalid argument') if kind='ingress' and the qdisc does
        # not exist. This behaviour must be refactored in pyroute2.
        if ((e.code == errno.ENOENT or
                (e.code == errno.EINVAL and kind == 'ingress')) and
                raise_qdisc_not_found is False):
            # NOTE(ralonsoh): return error code for testing purposes
            return e.code
        raise
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise ip_lib.NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def add_tc_policy_class(device, parent, classid, qdisc_type, namespace=None,
                        **kwargs):
    """Add/replace TC policy class"""
    try:
        index = ip_lib.get_link_id(device, namespace)
        with ip_lib.get_iproute(namespace) as ip:
            ip.tc('replace-class', kind=qdisc_type, index=index,
                  handle=classid, parent=parent, **kwargs)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise ip_lib.NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def list_tc_policy_classes(device, namespace=None):
    """List all TC policy classes of a device"""
    try:
        index = ip_lib.get_link_id(device, namespace)
        with ip_lib.get_iproute(namespace) as ip:
            return ip_lib.make_serializable(ip.get_classes(index=index))
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise ip_lib.NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def delete_tc_policy_class(device, parent, classid, namespace=None,
                           **kwargs):
    """Delete TC policy class"""
    try:
        index = ip_lib.get_link_id(device, namespace)
        with ip_lib.get_iproute(namespace) as ip:
            ip.tc('del-class', index=index, handle=classid, parent=parent,
                  **kwargs)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise ip_lib.NetworkNamespaceNotFound(netns_name=namespace)
        raise
    except pyroute2.NetlinkError as e:
        if e.code == errno.ENOENT:
            raise TrafficControlClassNotFound(classid=classid,
                                              namespace=namespace)


@privileged.default.entrypoint
def add_tc_filter_match32(device, parent, priority, class_id, keys,
                          protocol=None, namespace=None, **kwargs):
    """Add TC filter, type: match u32"""
    # NOTE(ralonsoh): by default (protocol=None), every packet is filtered.
    protocol = protocol or pyroute2_protocols.ETH_P_ALL
    try:
        index = ip_lib.get_link_id(device, namespace)
        with ip_lib.get_iproute(namespace) as ip:
            ip.tc('add-filter', kind='u32', index=index,
                  parent=parent, priority=priority, target=class_id,
                  protocol=protocol, keys=keys, **kwargs)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise ip_lib.NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def add_tc_filter_policy(device, parent, priority, rate, burst, mtu, action,
                         protocol=None, keys=None, flowid=1, namespace=None,
                         **kwargs):
    """Add TC filter, type: policy filter

    By default (protocol=None), that means every packet is shaped. "keys"
    and "target" (flowid) parameters are mandatory. If the filter is
    applied on a classless qdisc, "target" is irrelevant and a default value
    can be passed. If all packets must be shaped, an empty filter ("keys")
    can be passed.
    """
    keys = keys if keys else ['0x0/0x0']
    protocol = protocol or pyroute2_protocols.ETH_P_ALL
    try:
        index = ip_lib.get_link_id(device, namespace)
        with ip_lib.get_iproute(namespace) as ip:
            ip.tc('add-filter', kind='u32', index=index,
                  parent=parent, priority=priority, protocol=protocol,
                  rate=rate, burst=burst, mtu=mtu, action=action,
                  keys=keys, target=flowid, **kwargs)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise ip_lib.NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def list_tc_filters(device, parent, namespace=None, **kwargs):
    """List TC filters"""
    try:
        index = ip_lib.get_link_id(device, namespace)
        with ip_lib.get_iproute(namespace) as ip:
            return ip_lib.make_serializable(
                ip.get_filters(index=index, parent=parent, **kwargs))
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise ip_lib.NetworkNamespaceNotFound(netns_name=namespace)
        raise

# Copyright 2012 Nicira Networks, Inc.
# All Rights Reserved
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
#
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Dave Lapsley, Nicira Networks, Inc.
# @author: Aaron Rosen, Nicira Networks, Inc.


# TODO(bgh): We should break this into separate files.  It will just keep
# growing as we add more features :)

from copy import copy
import functools
import json
import hashlib
import logging
import random
import re
import uuid

from eventlet import semaphore
import NvpApiClient

#FIXME(danwent): I'd like this file to get to the point where it has
# no quantum-specific logic in it
from quantum.common import constants
from quantum.common import exceptions as exception

LOCAL_LOGGING = False
if LOCAL_LOGGING:
    from logging.handlers import SysLogHandler
    FORMAT = ("|%(levelname)s|%(filename)s|%(funcName)s|%(lineno)s"
              "|%(message)s")
    LOG = logging.getLogger(__name__)
    formatter = logging.Formatter(FORMAT)
    syslog = SysLogHandler(address="/dev/log")
    syslog.setFormatter(formatter)
    LOG.addHandler(syslog)
    LOG.setLevel(logging.DEBUG)
else:
    LOG = logging.getLogger("nvplib")
    LOG.setLevel(logging.INFO)

# TODO(bgh): it would be more efficient to use a bitmap
taken_context_ids = []

_net_type_cache = {}  # cache of {net_id: network_type}
# XXX Only cache default for now
_lqueue_cache = {}


def get_cluster_version(cluster):
    """Return major/minor version #"""
    # Get control-cluster nodes
    uri = "/ws.v1/control-cluster/node?_page_length=1&fields=uuid"
    try:
        res = do_single_request("GET", uri, cluster=cluster)
        res = json.loads(res)
    except NvpApiClient.NvpApiException:
        raise exception.QuantumException()
    if res["result_count"] == 0:
        return None
    node_uuid = res["results"][0]["uuid"]
    # Get control-cluster node status.  It's unsupported to have controllers
    # running different version so we just need the first node version.
    uri = "/ws.v1/control-cluster/node/%s/status" % node_uuid
    try:
        res = do_single_request("GET", uri, cluster=cluster)
        res = json.loads(res)
    except NvpApiClient.NvpApiException:
        raise exception.QuantumException()
    version_parts = res["version"].split(".")
    version = "%s.%s" % tuple(version_parts[:2])
    LOG.info("NVP controller cluster version: %s" % version)
    return version


def get_all_query_pages(path, c):
    need_more_results = True
    result_list = []
    page_cursor = None
    query_marker = "&" if (path.find("?") != -1) else "?"
    while need_more_results:
        page_cursor_str = (
            "_page_cursor=%s" % page_cursor if page_cursor else "")
        res = do_single_request("GET", "%s%s%s" %
                                (path, query_marker, page_cursor_str),
                                cluster=c)
        body = json.loads(res)
        page_cursor = body.get('page_cursor')
        if not page_cursor:
            need_more_results = False
        result_list.extend(body['results'])
    return result_list


def do_single_request(*args, **kwargs):
    """Issue a request to a specified cluster if specified via kwargs
       (cluster=<cluster>)."""
    cluster = kwargs["cluster"]
    return cluster.api_client.request(*args)


def do_multi_request(*args, **kwargs):
    """Issue a request to all clusters"""
    results = []
    clusters = kwargs["clusters"]
    for x in clusters:
        LOG.debug("Issuing request to cluster: %s" % x.name)
        rv = x.api_client.request(*args)
        results.append(rv)
    return results


# -------------------------------------------------------------------
# Network functions
# -------------------------------------------------------------------
def find_port_and_cluster(clusters, port_id):
    """Return (url, cluster_id) of port or (None, None) if port does not exist.
    """
    for c in clusters:
        query = "/ws.v1/lswitch/*/lport?uuid=%s&fields=*" % port_id
        LOG.debug("Looking for lswitch with port id \"%s\" on: %s"
                  % (port_id, c))
        try:
            res = do_single_request('GET', query, cluster=c)
        except Exception as e:
            LOG.error("get_port_cluster_and_url, exception: %s" % str(e))
            continue
        res = json.loads(res)
        if len(res["results"]) == 1:
            return (res["results"][0], c)
    return (None, None)


def find_lswitch_by_portid(clusters, port_id):
    port, cluster = find_port_and_cluster(clusters, port_id)
    if port and cluster:
        href = port["_href"].split('/')
        return (href[3], cluster)
    return (None, None)


def get_network(cluster, net_id):
    path = "/ws.v1/lswitch/%s" % net_id
    try:
        resp_obj = do_single_request("GET", path, cluster=cluster)
        network = json.loads(resp_obj)
        LOG.warning("### nw:%s", network)
    except NvpApiClient.ResourceNotFound:
        raise exception.NetworkNotFound(net_id=net_id)
    except NvpApiClient.NvpApiException:
        raise exception.QuantumException()
    LOG.debug("Got network \"%s\": %s" % (net_id, network))
    return network


def create_lswitch(cluster, lswitch_obj):
    LOG.info("Creating lswitch: %s" % lswitch_obj)
    # Warn if no tenant is specified
    found = "os_tid" in [x["scope"] for x in lswitch_obj["tags"]]
    if not found:
        LOG.warn("No tenant-id tag specified in logical switch: %s" % (
            lswitch_obj))
    uri = "/ws.v1/lswitch"
    try:
        resp_obj = do_single_request("POST", uri,
                                     json.dumps(lswitch_obj),
                                     cluster=cluster)
    except NvpApiClient.NvpApiException:
        raise exception.QuantumException()

    r = json.loads(resp_obj)
    d = {}
    d["net-id"] = r['uuid']
    d["net-name"] = r['display_name']
    LOG.debug("Created logical switch: %s" % d["net-id"])
    return d


def update_network(cluster, switch, **params):
    uri = "/ws.v1/lswitch/" + switch
    lswitch_obj = {}
    if params["network"]["name"]:
        lswitch_obj["display_name"] = params["network"]["name"]
    try:
        resp_obj = do_single_request("PUT", uri, json.dumps(lswitch_obj),
                                     cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Network not found, Error: %s" % str(e))
        raise exception.NetworkNotFound(net_id=network)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()

    obj = json.loads(resp_obj)
    return obj


def get_all_networks(cluster, tenant_id, networks):
    """Append the quantum network uuids we can find in the given cluster to
       "networks"
       """
    uri = "/ws.v1/lswitch?fields=*&tag=%s&tag_scope=os_tid" % tenant_id
    try:
        resp_obj = do_single_request("GET", uri, cluster=cluster)
    except NvpApiClient.NvpApiException:
        raise exception.QuantumException()
    if not resp_obj:
        return []
    lswitches = json.loads(resp_obj)["results"]
    networks_result = copy(networks)
    return networks_result


def query_networks(cluster, tenant_id, fields="*", tags=None):
    uri = "/ws.v1/lswitch?fields=%s" % fields
    if tags:
        for t in tags:
            uri += "&tag=%s&tag_scope=%s" % (t[0], t[1])
    try:
        resp_obj = do_single_request("GET", uri, cluster=cluster)
    except NvpApiClient.NvpApiException:
        raise exception.QuantumException()
    if not resp_obj:
        return []
    lswitches = json.loads(resp_obj)["results"]
    nets = [{'net-id': lswitch["uuid"], 'net-name': lswitch["display_name"]}
            for lswitch in lswitches]
    return nets


def delete_network(cluster, net_id, lswitch_id):
    delete_networks(cluster, net_id, [lswitch_id])


def delete_networks(cluster, net_id, lswitch_ids):
    if net_id in _net_type_cache:
        del _net_type_cache[net_id]
    for ls_id in lswitch_ids:
        path = "/ws.v1/lswitch/%s" % ls_id

        try:
            do_single_request("DELETE", path, cluster=cluster)
        except NvpApiClient.ResourceNotFound as e:
            LOG.error("Network not found, Error: %s" % str(e))
            raise exception.NetworkNotFound(net_id=ls_id)
        except NvpApiClient.NvpApiException as e:
            raise exception.QuantumException()


def create_network(tenant_id, net_name, **kwargs):
    clusters = kwargs["clusters"]
    # Default to the primary cluster
    cluster = clusters[0]

    transport_zone = kwargs.get("transport_zone",
                                cluster.default_tz_uuid)
    transport_type = kwargs.get("transport_type", "stt")
    lswitch_obj = {"display_name": net_name,
                   "transport_zones": [
                   {"zone_uuid": transport_zone,
                    "transport_type": transport_type}
                   ],
                   "tags": [{"tag": tenant_id, "scope": "os_tid"}]}

    net = create_lswitch(cluster, lswitch_obj)
    net['net-op-status'] = constants.NET_STATUS_ACTIVE
    return net


def query_ports(cluster, network, relations=None, fields="*", filters=None):
    uri = "/ws.v1/lswitch/" + network + "/lport?"
    if relations:
        uri += "relations=%s" % relations
    uri += "&fields=%s" % fields
    if filters and "attachment" in filters:
        uri += "&attachment_vif_uuid=%s" % filters["attachment"]
    try:
        resp_obj = do_single_request("GET", uri, cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Network not found, Error: %s" % str(e))
        raise exception.NetworkNotFound(net_id=network)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    return json.loads(resp_obj)["results"]


def delete_port(cluster, port):
    try:
        do_single_request("DELETE", port['_href'], cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port or Network not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port['uuid'])
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()


def get_port_by_quantum_tag(clusters, lswitch, quantum_tag):
    """Return (url, cluster_id) of port or raises ResourceNotFound
    """
    query = ("/ws.v1/lswitch/%s/lport?fields=admin_status_enabled,"
             "fabric_status_up,uuid&tag=%s&tag_scope=q_port_id"
             "&relations=LogicalPortStatus" % (lswitch, quantum_tag))

    LOG.debug("Looking for port with q_tag \"%s\" on: %s"
              % (quantum_tag, lswitch))
    for c in clusters:
        try:
            res_obj = do_single_request('GET', query, cluster=c)
        except Exception as e:
            continue
        res = json.loads(res_obj)
        if len(res["results"]) == 1:
            return (res["results"][0], c)

    LOG.error("Port or Network not found, Error: %s" % str(e))
    raise exception.PortNotFound(port_id=quantum_tag, net_id=lswitch)


def get_port_by_display_name(clusters, lswitch, display_name):
    """Return (url, cluster_id) of port or raises ResourceNotFound
    """
    query = ("/ws.v1/lswitch/%s/lport?display_name=%s&fields=*" %
             (lswitch, display_name))
    LOG.debug("Looking for port with display_name \"%s\" on: %s"
              % (display_name, lswitch))
    for c in clusters:
        try:
            res_obj = do_single_request('GET', query, cluster=c)
        except Exception as e:
            continue
        res = json.loads(res_obj)
        if len(res["results"]) == 1:
            return (res["results"][0], c)

    LOG.error("Port or Network not found, Error: %s" % str(e))
    raise exception.PortNotFound(port_id=display_name, net_id=lswitch)


def get_port(cluster, network, port, relations=None):
    LOG.info("get_port() %s %s" % (network, port))
    uri = "/ws.v1/lswitch/" + network + "/lport/" + port + "?"
    if relations:
        uri += "relations=%s" % relations
    try:
        resp_obj = do_single_request("GET", uri, cluster=cluster)
        port = json.loads(resp_obj)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port or Network not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port, net_id=network)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    return port


def update_port(network, port_id, **params):
    cluster = params["cluster"]
    lport_obj = {}

    admin_state_up = params['port'].get('admin_state_up')
    name = params["port"].get("name")
    device_id = params["port"].get("device_id")
    if admin_state_up:
        lport_obj["admin_status_enabled"] = admin_state_up
    if name:
        lport_obj["display_name"] = name

    if device_id:
        # device_id can be longer than 40 so we rehash it
        device_id = hashlib.sha1(device_id).hexdigest()
        lport_obj["tags"] = (
            [dict(scope='os_tid', tag=params["port"].get("tenant_id")),
             dict(scope='q_port_id', tag=params["port"]["id"]),
             dict(scope='vm_id', tag=device_id)])

    uri = "/ws.v1/lswitch/" + network + "/lport/" + port_id
    try:
        resp_obj = do_single_request("PUT", uri, json.dumps(lport_obj),
                                     cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port or Network not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port_id, net_id=network)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()

    obj = json.loads(resp_obj)
    obj["port-op-status"] = get_port_status(cluster, network, obj["uuid"])
    return obj


def create_port(tenant, **params):
    clusters = params["clusters"]
    dest_cluster = clusters[0]  # primary cluster

    ls_uuid = params["port"]["network_id"]
    # device_id can be longer than 40 so we rehash it
    device_id = hashlib.sha1(params["port"]["device_id"]).hexdigest()
    lport_obj = dict(
        admin_status_enabled=params["port"]["admin_state_up"],
        display_name=params["port"]["name"],
        tags=[dict(scope='os_tid', tag=tenant),
              dict(scope='q_port_id', tag=params["port"]["id"]),
              dict(scope='vm_id', tag=device_id)]
    )
    path = "/ws.v1/lswitch/" + ls_uuid + "/lport"

    try:
        resp_obj = do_single_request("POST", path, json.dumps(lport_obj),
                                     cluster=dest_cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Network not found, Error: %s" % str(e))
        raise exception.NetworkNotFound(net_id=params["port"]["network_id"])
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()

    result = json.loads(resp_obj)
    result['port-op-status'] = get_port_status(dest_cluster, ls_uuid,
                                               result['uuid'])

    params["port"].update({"admin_state_up": result["admin_status_enabled"],
                           "status": result["port-op-status"]})
    return (params["port"], result['uuid'])


def get_port_status(cluster, lswitch_id, port_id):
    """Retrieve the operational status of the port"""
    try:
        r = do_single_request("GET",
                              "/ws.v1/lswitch/%s/lport/%s/status" %
                              (lswitch_id, port_id), cluster=cluster)
        r = json.loads(r)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port_id, net_id=lswitch_id)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    if r['link_status_up'] is True:
        return constants.PORT_STATUS_ACTIVE
    else:
        return constants.PORT_STATUS_DOWN


def plug_interface(clusters, lswitch_id, port, type, attachment=None):
    dest_cluster = clusters[0]  # primary cluster
    uri = "/ws.v1/lswitch/" + lswitch_id + "/lport/" + port + "/attachment"

    lport_obj = {}
    if attachment:
        lport_obj["vif_uuid"] = attachment

    lport_obj["type"] = type
    try:
        resp_obj = do_single_request("PUT", uri, json.dumps(lport_obj),
                                     cluster=dest_cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port or Network not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port, net_id=lswitch_id)
    except NvpApiClient.Conflict as e:
        LOG.error("Conflict while making attachment to port, "
                  "Error: %s" % str(e))
        raise exception.AlreadyAttached(att_id=attachment,
                                        port_id=port,
                                        net_id=lswitch_id,
                                        att_port_id="UNKNOWN")
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()

    result = json.dumps(resp_obj)
    return result

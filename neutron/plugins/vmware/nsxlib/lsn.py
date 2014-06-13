# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 VMware, Inc.
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

import json

from neutron.common import exceptions as exception
from neutron.openstack.common import log
from neutron.plugins.vmware.api_client import exception as api_exc
from neutron.plugins.vmware.common import exceptions as nsx_exc
from neutron.plugins.vmware.common import utils
from neutron.plugins.vmware.nsxlib import _build_uri_path
from neutron.plugins.vmware.nsxlib import do_request

HTTP_GET = "GET"
HTTP_POST = "POST"
HTTP_DELETE = "DELETE"
HTTP_PUT = "PUT"

SERVICECLUSTER_RESOURCE = "edge-cluster"
LSERVICESNODE_RESOURCE = "lservices-node"
LSERVICESNODEPORT_RESOURCE = "lport/%s" % LSERVICESNODE_RESOURCE
SUPPORTED_METADATA_OPTIONS = ['metadata_proxy_shared_secret']

LOG = log.getLogger(__name__)


def service_cluster_exists(cluster, svc_cluster_id):
    exists = False
    try:
        exists = (
            svc_cluster_id and
            do_request(HTTP_GET,
                       _build_uri_path(SERVICECLUSTER_RESOURCE,
                                       resource_id=svc_cluster_id),
                       cluster=cluster) is not None)
    except exception.NotFound:
        pass
    return exists


def lsn_for_network_create(cluster, network_id):
    lsn_obj = {
        "edge_cluster_uuid": cluster.default_service_cluster_uuid,
        "tags": utils.get_tags(n_network_id=network_id)
    }
    return do_request(HTTP_POST,
                      _build_uri_path(LSERVICESNODE_RESOURCE),
                      json.dumps(lsn_obj),
                      cluster=cluster)["uuid"]


def lsn_for_network_get(cluster, network_id):
    filters = {"tag": network_id, "tag_scope": "n_network_id"}
    results = do_request(HTTP_GET,
                         _build_uri_path(LSERVICESNODE_RESOURCE,
                                         fields="uuid",
                                         filters=filters),
                         cluster=cluster)['results']
    if not results:
        raise exception.NotFound()
    elif len(results) == 1:
        return results[0]['uuid']


def lsn_delete(cluster, lsn_id):
    do_request(HTTP_DELETE,
               _build_uri_path(LSERVICESNODE_RESOURCE,
                               resource_id=lsn_id),
               cluster=cluster)


def lsn_port_host_entries_update(
    cluster, lsn_id, lsn_port_id, conf, hosts_data):
    hosts_obj = {'hosts': hosts_data}
    do_request(HTTP_PUT,
               _build_uri_path(LSERVICESNODEPORT_RESOURCE,
                               parent_resource_id=lsn_id,
                               resource_id=lsn_port_id,
                               extra_action=conf),
               json.dumps(hosts_obj),
               cluster=cluster)


def lsn_port_create(cluster, lsn_id, port_data):
    port_obj = {
        "ip_address": port_data["ip_address"],
        "mac_address": port_data["mac_address"],
        "tags": utils.get_tags(n_mac_address=port_data["mac_address"],
                               n_subnet_id=port_data["subnet_id"]),
        "type": "LogicalServicesNodePortConfig",
    }
    return do_request(HTTP_POST,
                      _build_uri_path(LSERVICESNODEPORT_RESOURCE,
                                      parent_resource_id=lsn_id),
                      json.dumps(port_obj),
                      cluster=cluster)["uuid"]


def lsn_port_delete(cluster, lsn_id, lsn_port_id):
    return do_request(HTTP_DELETE,
                      _build_uri_path(LSERVICESNODEPORT_RESOURCE,
                                      parent_resource_id=lsn_id,
                                      resource_id=lsn_port_id),
                      cluster=cluster)


def _lsn_port_get(cluster, lsn_id, filters):
    results = do_request(HTTP_GET,
                         _build_uri_path(LSERVICESNODEPORT_RESOURCE,
                                         parent_resource_id=lsn_id,
                                         fields="uuid",
                                         filters=filters),
                         cluster=cluster)['results']
    if not results:
        raise exception.NotFound()
    elif len(results) == 1:
        return results[0]['uuid']


def lsn_port_by_mac_get(cluster, lsn_id, mac_address):
    filters = {"tag": mac_address, "tag_scope": "n_mac_address"}
    return _lsn_port_get(cluster, lsn_id, filters)


def lsn_port_by_subnet_get(cluster, lsn_id, subnet_id):
    filters = {"tag": subnet_id, "tag_scope": "n_subnet_id"}
    return _lsn_port_get(cluster, lsn_id, filters)


def lsn_port_info_get(cluster, lsn_id, lsn_port_id):
    result = do_request(HTTP_GET,
                        _build_uri_path(LSERVICESNODEPORT_RESOURCE,
                                        parent_resource_id=lsn_id,
                                        resource_id=lsn_port_id),
                        cluster=cluster)
    for tag in result['tags']:
        if tag['scope'] == 'n_subnet_id':
            result['subnet_id'] = tag['tag']
            break
    return result


def lsn_port_plug_network(cluster, lsn_id, lsn_port_id, lswitch_port_id):
    patch_obj = {
        "type": "PatchAttachment",
        "peer_port_uuid": lswitch_port_id
    }
    try:
        do_request(HTTP_PUT,
                   _build_uri_path(LSERVICESNODEPORT_RESOURCE,
                                   parent_resource_id=lsn_id,
                                   resource_id=lsn_port_id,
                                   is_attachment=True),
                   json.dumps(patch_obj),
                   cluster=cluster)
    except api_exc.Conflict:
        # This restriction might be lifted at some point
        msg = (_("Attempt to plug Logical Services Node %(lsn)s into "
                 "network with port %(port)s failed. PatchAttachment "
                 "already exists with another port") %
               {'lsn': lsn_id, 'port': lswitch_port_id})
        LOG.exception(msg)
        raise nsx_exc.LsnConfigurationConflict(lsn_id=lsn_id)


def _lsn_configure_action(
    cluster, lsn_id, action, is_enabled, obj):
    lsn_obj = {"enabled": is_enabled}
    lsn_obj.update(obj)
    do_request(HTTP_PUT,
               _build_uri_path(LSERVICESNODE_RESOURCE,
                               resource_id=lsn_id,
                               extra_action=action),
               json.dumps(lsn_obj),
               cluster=cluster)


def _lsn_port_configure_action(
    cluster, lsn_id, lsn_port_id, action, is_enabled, obj):
    do_request(HTTP_PUT,
               _build_uri_path(LSERVICESNODE_RESOURCE,
                               resource_id=lsn_id,
                               extra_action=action),
               json.dumps({"enabled": is_enabled}),
               cluster=cluster)
    do_request(HTTP_PUT,
               _build_uri_path(LSERVICESNODEPORT_RESOURCE,
                               parent_resource_id=lsn_id,
                               resource_id=lsn_port_id,
                               extra_action=action),
               json.dumps(obj),
               cluster=cluster)


def _get_opts(name, value):
    return {"name": name, "value": str(value)}


def lsn_port_dhcp_configure(
        cluster, lsn_id, lsn_port_id, is_enabled=True, dhcp_options=None):
    dhcp_options = dhcp_options or {}
    opts = [_get_opts(key, val) for key, val in dhcp_options.iteritems()]
    dhcp_obj = {'options': opts}
    _lsn_port_configure_action(
        cluster, lsn_id, lsn_port_id, 'dhcp', is_enabled, dhcp_obj)


def lsn_metadata_configure(
        cluster, lsn_id, is_enabled=True, metadata_info=None):
    meta_obj = {
        'metadata_server_ip': metadata_info['metadata_server_ip'],
        'metadata_server_port': metadata_info['metadata_server_port'],
    }
    if metadata_info:
        opts = [
            _get_opts(opt, metadata_info[opt])
            for opt in SUPPORTED_METADATA_OPTIONS
            if metadata_info.get(opt)
        ]
        if opts:
            meta_obj["options"] = opts
    _lsn_configure_action(
        cluster, lsn_id, 'metadata-proxy', is_enabled, meta_obj)


def _lsn_port_host_action(
    cluster, lsn_id, lsn_port_id, host_obj, extra_action, action):
    do_request(HTTP_POST,
               _build_uri_path(LSERVICESNODEPORT_RESOURCE,
                               parent_resource_id=lsn_id,
                               resource_id=lsn_port_id,
                               extra_action=extra_action,
                               filters={"action": action}),
               json.dumps(host_obj),
               cluster=cluster)


def lsn_port_dhcp_host_add(cluster, lsn_id, lsn_port_id, host_data):
    _lsn_port_host_action(
        cluster, lsn_id, lsn_port_id, host_data, 'dhcp', 'add_host')


def lsn_port_dhcp_host_remove(cluster, lsn_id, lsn_port_id, host_data):
    _lsn_port_host_action(
        cluster, lsn_id, lsn_port_id, host_data, 'dhcp', 'remove_host')


def lsn_port_metadata_host_add(cluster, lsn_id, lsn_port_id, host_data):
    _lsn_port_host_action(
        cluster, lsn_id, lsn_port_id, host_data, 'metadata-proxy', 'add_host')


def lsn_port_metadata_host_remove(cluster, lsn_id, lsn_port_id, host_data):
    _lsn_port_host_action(cluster, lsn_id, lsn_port_id,
                          host_data, 'metadata-proxy', 'remove_host')

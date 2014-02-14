# Copyright 2014 VMware, Inc.
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

import json

from neutron.openstack.common import log
from neutron.plugins.vmware.common import utils
from neutron.plugins.vmware.nsxlib import _build_uri_path
from neutron.plugins.vmware.nsxlib import do_request
from neutron.plugins.vmware.nsxlib import get_all_query_pages
from neutron.plugins.vmware.nsxlib import switch

HTTP_GET = "GET"
HTTP_POST = "POST"
HTTP_DELETE = "DELETE"
HTTP_PUT = "PUT"

GWSERVICE_RESOURCE = "gateway-service"

LOG = log.getLogger(__name__)


def create_l2_gw_service(cluster, tenant_id, display_name, devices):
    """Create a NSX Layer-2 Network Gateway Service.

        :param cluster: The target NSX cluster
        :param tenant_id: Identifier of the Openstack tenant for which
        the gateway service.
        :param display_name: Descriptive name of this gateway service
        :param devices: List of transport node uuids (and network
        interfaces on them) to use for the network gateway service
        :raise NsxApiException: if there is a problem while communicating
        with the NSX controller
    """
    # NOTE(salvatore-orlando): This is a little confusing, but device_id in
    # NSX is actually the identifier a physical interface on the gateway
    # device, which in the Neutron API is referred as interface_name
    gateways = [{"transport_node_uuid": device['id'],
                 "device_id": device['interface_name'],
                 "type": "L2Gateway"} for device in devices]
    gwservice_obj = {
        "display_name": utils.check_and_truncate(display_name),
        "tags": utils.get_tags(os_tid=tenant_id),
        "gateways": gateways,
        "type": "L2GatewayServiceConfig"
    }
    return do_request(
        "POST", _build_uri_path(GWSERVICE_RESOURCE),
        json.dumps(gwservice_obj), cluster=cluster)


def plug_l2_gw_service(cluster, lswitch_id, lport_id,
                       gateway_id, vlan_id=None):
    """Plug a Layer-2 Gateway Attachment object in a logical port."""
    att_obj = {'type': 'L2GatewayAttachment',
               'l2_gateway_service_uuid': gateway_id}
    if vlan_id:
        att_obj['vlan_id'] = vlan_id
    return switch.plug_interface(cluster, lswitch_id, lport_id, att_obj)


def get_l2_gw_service(cluster, gateway_id):
    return do_request(
        "GET", _build_uri_path(GWSERVICE_RESOURCE,
                               resource_id=gateway_id),
        cluster=cluster)


def get_l2_gw_services(cluster, tenant_id=None,
                       fields=None, filters=None):
    actual_filters = dict(filters or {})
    if tenant_id:
        actual_filters['tag'] = tenant_id
        actual_filters['tag_scope'] = 'os_tid'
    return get_all_query_pages(
        _build_uri_path(GWSERVICE_RESOURCE,
                        filters=actual_filters),
        cluster)


def update_l2_gw_service(cluster, gateway_id, display_name):
    # TODO(salvatore-orlando): Allow updates for gateways too
    gwservice_obj = get_l2_gw_service(cluster, gateway_id)
    if not display_name:
        # Nothing to update
        return gwservice_obj
    gwservice_obj["display_name"] = utils.check_and_truncate(display_name)
    return do_request("PUT", _build_uri_path(GWSERVICE_RESOURCE,
                                             resource_id=gateway_id),
                      json.dumps(gwservice_obj), cluster=cluster)


def delete_l2_gw_service(cluster, gateway_id):
    do_request("DELETE", _build_uri_path(GWSERVICE_RESOURCE,
                                         resource_id=gateway_id),
               cluster=cluster)

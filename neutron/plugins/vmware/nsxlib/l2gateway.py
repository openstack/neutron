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

from oslo_serialization import jsonutils

from neutron.openstack.common import log
from neutron.plugins.vmware.api_client import exception as api_exc
from neutron.plugins.vmware.common import exceptions as nsx_exc
from neutron.plugins.vmware.common import utils
from neutron.plugins.vmware import nsxlib
from neutron.plugins.vmware.nsxlib import switch

HTTP_GET = "GET"
HTTP_POST = "POST"
HTTP_DELETE = "DELETE"
HTTP_PUT = "PUT"

GWSERVICE_RESOURCE = "gateway-service"
TRANSPORTNODE_RESOURCE = "transport-node"

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
    return nsxlib.do_request(
        HTTP_POST, nsxlib._build_uri_path(GWSERVICE_RESOURCE),
        jsonutils.dumps(gwservice_obj), cluster=cluster)


def plug_l2_gw_service(cluster, lswitch_id, lport_id,
                       gateway_id, vlan_id=None):
    """Plug a Layer-2 Gateway Attachment object in a logical port."""
    att_obj = {'type': 'L2GatewayAttachment',
               'l2_gateway_service_uuid': gateway_id}
    if vlan_id:
        att_obj['vlan_id'] = vlan_id
    return switch.plug_interface(cluster, lswitch_id, lport_id, att_obj)


def get_l2_gw_service(cluster, gateway_id):
    return nsxlib.do_request(
        HTTP_GET, nsxlib._build_uri_path(GWSERVICE_RESOURCE,
                                         resource_id=gateway_id),
        cluster=cluster)


def get_l2_gw_services(cluster, tenant_id=None,
                       fields=None, filters=None):
    actual_filters = dict(filters or {})
    if tenant_id:
        actual_filters['tag'] = tenant_id
        actual_filters['tag_scope'] = 'os_tid'
    return nsxlib.get_all_query_pages(
        nsxlib._build_uri_path(GWSERVICE_RESOURCE,
                               filters=actual_filters),
        cluster)


def update_l2_gw_service(cluster, gateway_id, display_name):
    # TODO(salvatore-orlando): Allow updates for gateways too
    gwservice_obj = get_l2_gw_service(cluster, gateway_id)
    if not display_name:
        # Nothing to update
        return gwservice_obj
    gwservice_obj["display_name"] = utils.check_and_truncate(display_name)
    return nsxlib.do_request(HTTP_PUT,
                             nsxlib._build_uri_path(GWSERVICE_RESOURCE,
                                                    resource_id=gateway_id),
                             jsonutils.dumps(gwservice_obj), cluster=cluster)


def delete_l2_gw_service(cluster, gateway_id):
    nsxlib.do_request(HTTP_DELETE,
                      nsxlib._build_uri_path(GWSERVICE_RESOURCE,
                                             resource_id=gateway_id),
                      cluster=cluster)


def _build_gateway_device_body(tenant_id, display_name, neutron_id,
                               connector_type, connector_ip,
                               client_certificate, tz_uuid):

    connector_type_mappings = {
        utils.NetworkTypes.STT: "STTConnector",
        utils.NetworkTypes.GRE: "GREConnector",
        utils.NetworkTypes.BRIDGE: "BridgeConnector",
        'ipsec%s' % utils.NetworkTypes.STT: "IPsecSTT",
        'ipsec%s' % utils.NetworkTypes.GRE: "IPsecGRE"}
    nsx_connector_type = connector_type_mappings.get(connector_type)
    body = {"display_name": utils.check_and_truncate(display_name),
            "tags": utils.get_tags(os_tid=tenant_id,
                                   q_gw_dev_id=neutron_id),
            "admin_status_enabled": True}

    if connector_ip and nsx_connector_type:
        body["transport_connectors"] = [
            {"transport_zone_uuid": tz_uuid,
             "ip_address": connector_ip,
             "type": nsx_connector_type}]

    if client_certificate:
        body["credential"] = {"client_certificate":
                              {"pem_encoded": client_certificate},
                              "type": "SecurityCertificateCredential"}
    return body


def create_gateway_device(cluster, tenant_id, display_name, neutron_id,
                          tz_uuid, connector_type, connector_ip,
                          client_certificate):
    body = _build_gateway_device_body(tenant_id, display_name, neutron_id,
                                      connector_type, connector_ip,
                                      client_certificate, tz_uuid)
    try:
        return nsxlib.do_request(
            HTTP_POST, nsxlib._build_uri_path(TRANSPORTNODE_RESOURCE),
            jsonutils.dumps(body, sort_keys=True), cluster=cluster)
    except api_exc.InvalidSecurityCertificate:
        raise nsx_exc.InvalidSecurityCertificate()


def update_gateway_device(cluster, gateway_id, tenant_id,
                          display_name, neutron_id,
                          tz_uuid, connector_type, connector_ip,
                          client_certificate):
    body = _build_gateway_device_body(tenant_id, display_name, neutron_id,
                                      connector_type, connector_ip,
                                      client_certificate, tz_uuid)
    try:
        return nsxlib.do_request(
            HTTP_PUT,
            nsxlib._build_uri_path(TRANSPORTNODE_RESOURCE,
                                   resource_id=gateway_id),
            jsonutils.dumps(body, sort_keys=True), cluster=cluster)
    except api_exc.InvalidSecurityCertificate:
        raise nsx_exc.InvalidSecurityCertificate()


def delete_gateway_device(cluster, device_uuid):
    return nsxlib.do_request(HTTP_DELETE,
                             nsxlib._build_uri_path(TRANSPORTNODE_RESOURCE,
                                                    device_uuid),
                             cluster=cluster)


def get_gateway_device_status(cluster, device_uuid):
    status_res = nsxlib.do_request(HTTP_GET,
                                   nsxlib._build_uri_path(
                                       TRANSPORTNODE_RESOURCE,
                                       device_uuid,
                                       extra_action='status'),
                                   cluster=cluster)
    # Returns the connection status
    return status_res['connection']['connected']


def get_gateway_devices_status(cluster, tenant_id=None):
    if tenant_id:
        gw_device_query_path = nsxlib._build_uri_path(
            TRANSPORTNODE_RESOURCE,
            fields="uuid,tags",
            relations="TransportNodeStatus",
            filters={'tag': tenant_id,
                     'tag_scope': 'os_tid'})
    else:
        gw_device_query_path = nsxlib._build_uri_path(
            TRANSPORTNODE_RESOURCE,
            fields="uuid,tags",
            relations="TransportNodeStatus")

    response = nsxlib.get_all_query_pages(gw_device_query_path, cluster)
    results = {}
    for item in response:
        results[item['uuid']] = (item['_relations']['TransportNodeStatus']
                                 ['connection']['connected'])
    return results

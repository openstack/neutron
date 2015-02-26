# Copyright (c) 2014 Freescale Semiconductor
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_log import log as logging

from neutron.common import constants as n_const
from neutron.common import log
from neutron.extensions import portbindings
from neutron.i18n import _LI
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.freescale import config  # noqa


LOG = logging.getLogger(__name__)


class FslsdnMechanismDriver(api.MechanismDriver):

    """Freescale SDN OS Mechanism Driver for ML2 Plugin."""

    @log.log
    def initialize(self):
        """Initialize the Mechanism driver."""

        self.vif_type = portbindings.VIF_TYPE_OVS
        self.vif_details = {portbindings.CAP_PORT_FILTER: True}
        LOG.info(_LI("Initializing CRD client... "))
        self._crdclient = config.get_crdclient()

    # Network Management
    @staticmethod
    @log.log
    def _prepare_crd_network(network, segments):
        """Helper function to create 'network' data."""

        return {'network':
                {'network_id': network['id'],
                 'tenant_id': network['tenant_id'],
                 'name': network['name'],
                 'status': network['status'],
                 'admin_state_up': network['admin_state_up'],
                 'segments': segments,
                 }}

    def create_network_postcommit(self, context):
        """Send create_network data to CRD service."""

        network = context.current
        segments = context.network_segments
        body = self._prepare_crd_network(network, segments)
        self._crdclient.create_network(body=body)
        LOG.debug("create_network update sent to CRD Server: %s", body)

    def update_network_postcommit(self, context):
        """Send update_network data to CRD service."""

        network = context.current
        segments = context.network_segments
        body = self._prepare_crd_network(network, segments)
        self._crdclient.update_network(network['id'], body=body)
        LOG.debug("update_network update sent to CRD Server: %s", body)

    def delete_network_postcommit(self, context):
        """Send delete_network data to CRD service."""

        network = context.current
        self._crdclient.delete_network(network['id'])
        LOG.debug(
            "delete_network update sent to CRD Server: %s",
            network['id'])

    # Port Management
    @staticmethod
    def _prepare_crd_port(port):
        """Helper function to prepare 'port' data."""

        crd_subnet_id = ''
        crd_ipaddress = ''
        crd_sec_grps = ''
        # Since CRD accepts one Fixed IP,
        # so handle only one fixed IP per port.
        if len(port['fixed_ips']) > 1:
            LOG.debug("More than one fixed IP exists - using first one.")
        # check empty fixed_ips list, move on if one or more exists
        if len(port['fixed_ips']) != 0:
            crd_subnet_id = port['fixed_ips'][0]['subnet_id']
            crd_ipaddress = port['fixed_ips'][0]['ip_address']
            LOG.debug("Handling fixed IP {subnet_id:%(subnet)s, "
                      "ip_address:%(ip)s}",
                      {'subnet': crd_subnet_id, 'ip': crd_ipaddress})
        else:
            LOG.debug("No fixed IPs found.")
        if 'security_groups' in port:
            crd_sec_grps = ','.join(port['security_groups'])
        return {'port':
                {'port_id': port['id'],
                 'tenant_id': port['tenant_id'],
                 'name': port['name'],
                 'network_id': port['network_id'],
                 'subnet_id': crd_subnet_id,
                 'mac_address': port['mac_address'],
                 'device_id': port['device_id'],
                 'ip_address': crd_ipaddress,
                 'admin_state_up': port['admin_state_up'],
                 'status': port['status'],
                 'device_owner': port['device_owner'],
                 'security_groups': crd_sec_grps,
                 }}

    def create_port_postcommit(self, context):
        """Send create_port data to CRD service."""

        port = context.current
        body = self._prepare_crd_port(port)
        self._crdclient.create_port(body=body)
        LOG.debug("create_port update sent to CRD Server: %s", body)

    def delete_port_postcommit(self, context):
        """Send delete_port data to CRD service."""

        port = context.current
        self._crdclient.delete_port(port['id'])
        LOG.debug("delete_port update sent to CRD Server: %s", port['id'])

    # Subnet Management
    @staticmethod
    @log.log
    def _prepare_crd_subnet(subnet):
        """Helper function to prepare 'subnet' data."""

        crd_allocation_pools = ''
        crd_dns_nameservers = ''
        crd_host_routes = ''
        # Handling Allocation IPs
        if 'allocation_pools' in subnet:
            a_pools = subnet['allocation_pools']
            crd_allocation_pools = ','.join(["%s-%s" % (p['start'],
                                                        p['end'])
                                             for p in a_pools])
        # Handling Host Routes
        if 'host_routes' in subnet:
            crd_host_routes = ','.join(["%s-%s" % (r['destination'],
                                                   r['nexthop'])
                                        for r in subnet['host_routes']])
        # Handling DNS Nameservers
        if 'dns_nameservers' in subnet:
            crd_dns_nameservers = ','.join(subnet['dns_nameservers'])
        # return Subnet Data
        return {'subnet':
                {'subnet_id': subnet['id'],
                 'tenant_id': subnet['tenant_id'],
                 'name': subnet['name'],
                 'network_id': subnet['network_id'],
                 'ip_version': subnet['ip_version'],
                 'cidr': subnet['cidr'],
                 'gateway_ip': subnet['gateway_ip'],
                 'dns_nameservers': crd_dns_nameservers,
                 'allocation_pools': crd_allocation_pools,
                 'host_routes': crd_host_routes,
                 }}

    def create_subnet_postcommit(self, context):
        """Send create_subnet data to CRD service."""

        subnet = context.current
        body = self._prepare_crd_subnet(subnet)
        self._crdclient.create_subnet(body=body)
        LOG.debug("create_subnet update sent to CRD Server: %s", body)

    def update_subnet_postcommit(self, context):
        """Send update_subnet data to CRD service."""

        subnet = context.current
        body = self._prepare_crd_subnet(subnet)
        self._crdclient.update_subnet(subnet['id'], body=body)
        LOG.debug("update_subnet update sent to CRD Server: %s", body)

    def delete_subnet_postcommit(self, context):
        """Send delete_subnet data to CRD service."""

        subnet = context.current
        self._crdclient.delete_subnet(subnet['id'])
        LOG.debug("delete_subnet update sent to CRD Server: %s", subnet['id'])

    def bind_port(self, context):
        """Set porting binding data for use with nova."""

        LOG.debug("Attempting to bind port %(port)s on "
                  "network %(network)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        # Prepared porting binding data
        for segment in context.segments_to_bind:
            if self.check_segment(segment):
                context.set_binding(segment[api.ID],
                                    self.vif_type,
                                    self.vif_details,
                                    status=n_const.PORT_STATUS_ACTIVE)
                LOG.debug("Bound using segment: %s", segment)
                return
            else:
                LOG.debug("Refusing to bind port for segment ID %(id)s, "
                          "segment %(seg)s, phys net %(physnet)s, and "
                          "network type %(nettype)s",
                          {'id': segment[api.ID],
                           'seg': segment[api.SEGMENTATION_ID],
                           'physnet': segment[api.PHYSICAL_NETWORK],
                           'nettype': segment[api.NETWORK_TYPE]})

    @log.log
    def check_segment(self, segment):
        """Verify a segment is valid for the FSL SDN MechanismDriver."""

        return segment[api.NETWORK_TYPE] in [constants.TYPE_VLAN,
                                             constants.TYPE_VXLAN]

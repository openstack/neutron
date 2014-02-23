# Copyright 2014 Citrix Systems, Inc.
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

from oslo.config import cfg

from neutron.api.v2 import attributes
from neutron.db.loadbalancer import loadbalancer_db
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services.loadbalancer.drivers import abstract_driver
from neutron.services.loadbalancer.drivers.netscaler import ncc_client

LOG = logging.getLogger(__name__)

NETSCALER_CC_OPTS = [
    cfg.StrOpt(
        'netscaler_ncc_uri',
        help=_('The URL to reach the NetScaler Control Center Server.'),
    ),
    cfg.StrOpt(
        'netscaler_ncc_username',
        help=_('Username to login to the NetScaler Control Center Server.'),
    ),
    cfg.StrOpt(
        'netscaler_ncc_password',
        help=_('Password to login to the NetScaler Control Center Server.'),
    )
]

cfg.CONF.register_opts(NETSCALER_CC_OPTS, 'netscaler_driver')

VIPS_RESOURCE = 'vips'
VIP_RESOURCE = 'vip'
POOLS_RESOURCE = 'pools'
POOL_RESOURCE = 'pool'
POOLMEMBERS_RESOURCE = 'members'
POOLMEMBER_RESOURCE = 'member'
MONITORS_RESOURCE = 'healthmonitors'
MONITOR_RESOURCE = 'healthmonitor'
POOLSTATS_RESOURCE = 'statistics'
PROV_SEGMT_ID = 'provider:segmentation_id'
PROV_NET_TYPE = 'provider:network_type'
DRIVER_NAME = 'netscaler_driver'


class NetScalerPluginDriver(abstract_driver.LoadBalancerAbstractDriver):

    """NetScaler LBaaS Plugin driver class."""

    def __init__(self, plugin):
        self.plugin = plugin
        ncc_uri = cfg.CONF.netscaler_driver.netscaler_ncc_uri
        ncc_username = cfg.CONF.netscaler_driver.netscaler_ncc_username
        ncc_password = cfg.CONF.netscaler_driver.netscaler_ncc_password
        self.client = ncc_client.NSClient(ncc_uri,
                                          ncc_username,
                                          ncc_password)

    def create_vip(self, context, vip):
        """Create a vip on a NetScaler device."""
        network_info = self._get_vip_network_info(context, vip)
        ncc_vip = self._prepare_vip_for_creation(vip)
        ncc_vip = dict(ncc_vip.items() + network_info.items())
        msg = _("NetScaler driver vip creation: %s") % repr(ncc_vip)
        LOG.debug(msg)
        status = constants.ACTIVE
        try:
            self.client.create_resource(context.tenant_id, VIPS_RESOURCE,
                                        VIP_RESOURCE, ncc_vip)
        except ncc_client.NCCException:
            status = constants.ERROR
        self.plugin.update_status(context, loadbalancer_db.Vip, vip["id"],
                                  status)

    def update_vip(self, context, old_vip, vip):
        """Update a vip on a NetScaler device."""
        update_vip = self._prepare_vip_for_update(vip)
        resource_path = "%s/%s" % (VIPS_RESOURCE, vip["id"])
        msg = (_("NetScaler driver vip %(vip_id)s update: %(vip_obj)s") %
               {"vip_id": vip["id"], "vip_obj": repr(vip)})
        LOG.debug(msg)
        status = constants.ACTIVE
        try:
            self.client.update_resource(context.tenant_id, resource_path,
                                        VIP_RESOURCE, update_vip)
        except ncc_client.NCCException:
            status = constants.ERROR
        self.plugin.update_status(context, loadbalancer_db.Vip, old_vip["id"],
                                  status)

    def delete_vip(self, context, vip):
        """Delete a vip on a NetScaler device."""
        resource_path = "%s/%s" % (VIPS_RESOURCE, vip["id"])
        msg = _("NetScaler driver vip removal: %s") % vip["id"]
        LOG.debug(msg)
        try:
            self.client.remove_resource(context.tenant_id, resource_path)
        except ncc_client.NCCException:
            self.plugin.update_status(context, loadbalancer_db.Vip,
                                      vip["id"],
                                      constants.ERROR)
        else:
            self.plugin._delete_db_vip(context, vip['id'])

    def create_pool(self, context, pool):
        """Create a pool on a NetScaler device."""
        network_info = self._get_pool_network_info(context, pool)
        #allocate a snat port/ipaddress on the subnet if one doesn't exist
        self._create_snatport_for_subnet_if_not_exists(context,
                                                       pool['tenant_id'],
                                                       pool['subnet_id'],
                                                       network_info)
        ncc_pool = self._prepare_pool_for_creation(pool)
        ncc_pool = dict(ncc_pool.items() + network_info.items())
        msg = _("NetScaler driver pool creation: %s") % repr(ncc_pool)
        LOG.debug(msg)
        status = constants.ACTIVE
        try:
            self.client.create_resource(context.tenant_id, POOLS_RESOURCE,
                                        POOL_RESOURCE, ncc_pool)
        except ncc_client.NCCException:
            status = constants.ERROR
        self.plugin.update_status(context, loadbalancer_db.Pool,
                                  ncc_pool["id"], status)

    def update_pool(self, context, old_pool, pool):
        """Update a pool on a NetScaler device."""
        ncc_pool = self._prepare_pool_for_update(pool)
        resource_path = "%s/%s" % (POOLS_RESOURCE, old_pool["id"])
        msg = (_("NetScaler driver pool %(pool_id)s update: %(pool_obj)s") %
               {"pool_id": old_pool["id"], "pool_obj": repr(ncc_pool)})
        LOG.debug(msg)
        status = constants.ACTIVE
        try:
            self.client.update_resource(context.tenant_id, resource_path,
                                        POOL_RESOURCE, ncc_pool)
        except ncc_client.NCCException:
            status = constants.ERROR
        self.plugin.update_status(context, loadbalancer_db.Pool,
                                  old_pool["id"], status)

    def delete_pool(self, context, pool):
        """Delete a pool on a NetScaler device."""
        resource_path = "%s/%s" % (POOLS_RESOURCE, pool['id'])
        msg = _("NetScaler driver pool removal: %s") % pool["id"]
        LOG.debug(msg)
        try:
            self.client.remove_resource(context.tenant_id, resource_path)
        except ncc_client.NCCException:
            self.plugin.update_status(context, loadbalancer_db.Pool,
                                      pool["id"],
                                      constants.ERROR)
        else:
            self.plugin._delete_db_pool(context, pool['id'])
            self._remove_snatport_for_subnet_if_not_used(context,
                                                         pool['tenant_id'],
                                                         pool['subnet_id'])

    def create_member(self, context, member):
        """Create a pool member on a NetScaler device."""
        ncc_member = self._prepare_member_for_creation(member)
        msg = (_("NetScaler driver poolmember creation: %s") %
               repr(ncc_member))
        LOG.info(msg)
        status = constants.ACTIVE
        try:
            self.client.create_resource(context.tenant_id,
                                        POOLMEMBERS_RESOURCE,
                                        POOLMEMBER_RESOURCE,
                                        ncc_member)
        except ncc_client.NCCException:
            status = constants.ERROR
        self.plugin.update_status(context, loadbalancer_db.Member,
                                  member["id"], status)

    def update_member(self, context, old_member, member):
        """Update a pool member on a NetScaler device."""
        ncc_member = self._prepare_member_for_update(member)
        resource_path = "%s/%s" % (POOLMEMBERS_RESOURCE, old_member["id"])
        msg = (_("NetScaler driver poolmember %(member_id)s update:"
                 " %(member_obj)s") %
               {"member_id": old_member["id"],
                "member_obj": repr(ncc_member)})
        LOG.debug(msg)
        status = constants.ACTIVE
        try:
            self.client.update_resource(context.tenant_id, resource_path,
                                        POOLMEMBER_RESOURCE, ncc_member)
        except ncc_client.NCCException:
            status = constants.ERROR
        self.plugin.update_status(context, loadbalancer_db.Member,
                                  old_member["id"], status)

    def delete_member(self, context, member):
        """Delete a pool member on a NetScaler device."""
        resource_path = "%s/%s" % (POOLMEMBERS_RESOURCE, member['id'])
        msg = (_("NetScaler driver poolmember removal: %s") %
               member["id"])
        LOG.debug(msg)
        try:
            self.client.remove_resource(context.tenant_id, resource_path)
        except ncc_client.NCCException:
            self.plugin.update_status(context, loadbalancer_db.Member,
                                      member["id"],
                                      constants.ERROR)
        else:
            self.plugin._delete_db_member(context, member['id'])

    def create_pool_health_monitor(self, context, health_monitor, pool_id):
        """Create a pool health monitor on a NetScaler device."""
        ncc_hm = self._prepare_healthmonitor_for_creation(health_monitor,
                                                          pool_id)
        resource_path = "%s/%s/%s" % (POOLS_RESOURCE, pool_id,
                                      MONITORS_RESOURCE)
        msg = (_("NetScaler driver healthmonitor creation for pool %(pool_id)s"
                 ": %(monitor_obj)s") %
               {"pool_id": pool_id,
                "monitor_obj": repr(ncc_hm)})
        LOG.debug(msg)
        status = constants.ACTIVE
        try:
            self.client.create_resource(context.tenant_id, resource_path,
                                        MONITOR_RESOURCE,
                                        ncc_hm)
        except ncc_client.NCCException:
            status = constants.ERROR
        self.plugin.update_pool_health_monitor(context,
                                               health_monitor['id'],
                                               pool_id,
                                               status, "")

    def update_pool_health_monitor(self, context, old_health_monitor,
                                   health_monitor, pool_id):
        """Update a pool health monitor on a NetScaler device."""
        ncc_hm = self._prepare_healthmonitor_for_update(health_monitor)
        resource_path = "%s/%s" % (MONITORS_RESOURCE,
                                   old_health_monitor["id"])
        msg = (_("NetScaler driver healthmonitor %(monitor_id)s update: "
                 "%(monitor_obj)s") %
               {"monitor_id": old_health_monitor["id"],
                "monitor_obj": repr(ncc_hm)})
        LOG.debug(msg)
        status = constants.ACTIVE
        try:
            self.client.update_resource(context.tenant_id, resource_path,
                                        MONITOR_RESOURCE, ncc_hm)
        except ncc_client.NCCException:
            status = constants.ERROR
        self.plugin.update_pool_health_monitor(context,
                                               old_health_monitor['id'],
                                               pool_id,
                                               status, "")

    def delete_pool_health_monitor(self, context, health_monitor, pool_id):
        """Delete a pool health monitor on a NetScaler device."""
        resource_path = "%s/%s/%s/%s" % (POOLS_RESOURCE, pool_id,
                                         MONITORS_RESOURCE,
                                         health_monitor["id"])
        msg = (_("NetScaler driver healthmonitor %(monitor_id)s"
                 "removal for pool %(pool_id)s") %
               {"monitor_id": health_monitor["id"],
                "pool_id": pool_id})
        LOG.debug(msg)
        try:
            self.client.remove_resource(context.tenant_id, resource_path)
        except ncc_client.NCCException:
            self.plugin.update_pool_health_monitor(context,
                                                   health_monitor['id'],
                                                   pool_id,
                                                   constants.ERROR, "")
        else:
            self.plugin._delete_db_pool_health_monitor(context,
                                                       health_monitor['id'],
                                                       pool_id)

    def stats(self, context, pool_id):
        """Retrieve pool statistics from the NetScaler device."""
        resource_path = "%s/%s" % (POOLSTATS_RESOURCE, pool_id)
        msg = _("NetScaler driver pool stats retrieval: %s") % pool_id
        LOG.debug(msg)
        try:
            stats = self.client.retrieve_resource(context.tenant_id,
                                                  resource_path)[1]
        except ncc_client.NCCException:
            self.plugin.update_status(context, loadbalancer_db.Pool,
                                      pool_id, constants.ERROR)
        else:
            return stats

    def _prepare_vip_for_creation(self, vip):
        creation_attrs = {
            'id': vip['id'],
            'tenant_id': vip['tenant_id'],
            'protocol': vip['protocol'],
            'address': vip['address'],
            'protocol_port': vip['protocol_port'],
        }
        if 'session_persistence' in vip:
            creation_attrs['session_persistence'] = vip['session_persistence']
        update_attrs = self._prepare_vip_for_update(vip)
        creation_attrs.update(update_attrs)
        return creation_attrs

    def _prepare_vip_for_update(self, vip):
        return {
            'name': vip['name'],
            'description': vip['description'],
            'pool_id': vip['pool_id'],
            'connection_limit': vip['connection_limit'],
            'admin_state_up': vip['admin_state_up']
        }

    def _prepare_pool_for_creation(self, pool):
        creation_attrs = {
            'id': pool['id'],
            'tenant_id': pool['tenant_id'],
            'vip_id': pool['vip_id'],
            'protocol': pool['protocol'],
            'subnet_id': pool['subnet_id'],
        }
        update_attrs = self._prepare_pool_for_update(pool)
        creation_attrs.update(update_attrs)
        return creation_attrs

    def _prepare_pool_for_update(self, pool):
        return {
            'name': pool['name'],
            'description': pool['description'],
            'lb_method': pool['lb_method'],
            'admin_state_up': pool['admin_state_up']
        }

    def _prepare_member_for_creation(self, member):
        creation_attrs = {
            'id': member['id'],
            'tenant_id': member['tenant_id'],
            'address': member['address'],
            'protocol_port': member['protocol_port'],
        }
        update_attrs = self._prepare_member_for_update(member)
        creation_attrs.update(update_attrs)
        return creation_attrs

    def _prepare_member_for_update(self, member):
        return {
            'pool_id': member['pool_id'],
            'weight': member['weight'],
            'admin_state_up': member['admin_state_up']
        }

    def _prepare_healthmonitor_for_creation(self, health_monitor, pool_id):
        creation_attrs = {
            'id': health_monitor['id'],
            'tenant_id': health_monitor['tenant_id'],
            'type': health_monitor['type'],
        }
        update_attrs = self._prepare_healthmonitor_for_update(health_monitor)
        creation_attrs.update(update_attrs)
        return creation_attrs

    def _prepare_healthmonitor_for_update(self, health_monitor):
        ncc_hm = {
            'delay': health_monitor['delay'],
            'timeout': health_monitor['timeout'],
            'max_retries': health_monitor['max_retries'],
            'admin_state_up': health_monitor['admin_state_up']
        }
        if health_monitor['type'] in ['HTTP', 'HTTPS']:
            ncc_hm['http_method'] = health_monitor['http_method']
            ncc_hm['url_path'] = health_monitor['url_path']
            ncc_hm['expected_codes'] = health_monitor['expected_codes']
        return ncc_hm

    def _get_network_info(self, context, entity):
        network_info = {}
        subnet_id = entity['subnet_id']
        subnet = self.plugin._core_plugin.get_subnet(context, subnet_id)
        network_id = subnet['network_id']
        network = self.plugin._core_plugin.get_network(context, network_id)
        network_info['network_id'] = network_id
        network_info['subnet_id'] = subnet_id
        if PROV_NET_TYPE in network:
            network_info['network_type'] = network[PROV_NET_TYPE]
        if PROV_SEGMT_ID in network:
            network_info['segmentation_id'] = network[PROV_SEGMT_ID]
        return network_info

    def _get_vip_network_info(self, context, vip):
        network_info = self._get_network_info(context, vip)
        network_info['port_id'] = vip['port_id']
        return network_info

    def _get_pool_network_info(self, context, pool):
        return self._get_network_info(context, pool)

    def _get_pools_on_subnet(self, context, tenant_id, subnet_id):
        filter_dict = {'subnet_id': [subnet_id], 'tenant_id': [tenant_id]}
        return self.plugin.get_pools(context, filters=filter_dict)

    def _get_snatport_for_subnet(self, context, tenant_id, subnet_id):
        device_id = '_lb-snatport-' + subnet_id
        subnet = self.plugin._core_plugin.get_subnet(context, subnet_id)
        network_id = subnet['network_id']
        msg = (_("Filtering ports based on network_id=%(network_id)s, "
                 "tenant_id=%(tenant_id)s, device_id=%(device_id)s") %
               {'network_id': network_id,
                'tenant_id': tenant_id,
                'device_id': device_id})
        LOG.debug(msg)
        filter_dict = {
            'network_id': [network_id],
            'tenant_id': [tenant_id],
            'device_id': [device_id],
            'device-owner': [DRIVER_NAME]
        }
        ports = self.plugin._core_plugin.get_ports(context,
                                                   filters=filter_dict)
        if ports:
            msg = _("Found an existing SNAT port for subnet %s") % subnet_id
            LOG.info(msg)
            return ports[0]
        msg = _("Found no SNAT ports for subnet %s") % subnet_id
        LOG.info(msg)

    def _create_snatport_for_subnet(self, context, tenant_id, subnet_id,
                                    ip_address):
        subnet = self.plugin._core_plugin.get_subnet(context, subnet_id)
        fixed_ip = {'subnet_id': subnet['id']}
        if ip_address and ip_address != attributes.ATTR_NOT_SPECIFIED:
            fixed_ip['ip_address'] = ip_address
        port_data = {
            'tenant_id': tenant_id,
            'name': '_lb-snatport-' + subnet_id,
            'network_id': subnet['network_id'],
            'mac_address': attributes.ATTR_NOT_SPECIFIED,
            'admin_state_up': False,
            'device_id': '_lb-snatport-' + subnet_id,
            'device_owner': DRIVER_NAME,
            'fixed_ips': [fixed_ip],
        }
        port = self.plugin._core_plugin.create_port(context,
                                                    {'port': port_data})
        msg = _("Created SNAT port: %s") % repr(port)
        LOG.info(msg)
        return port

    def _remove_snatport_for_subnet(self, context, tenant_id, subnet_id):
        port = self._get_snatport_for_subnet(context, tenant_id, subnet_id)
        if port:
            self.plugin._core_plugin.delete_port(context, port['id'])
            msg = _("Removed SNAT port: %s") % repr(port)
            LOG.info(msg)

    def _create_snatport_for_subnet_if_not_exists(self, context, tenant_id,
                                                  subnet_id, network_info):
        port = self._get_snatport_for_subnet(context, tenant_id, subnet_id)
        if not port:
            msg = _("No SNAT port found for subnet %s."
                    " Creating one...") % subnet_id
            LOG.info(msg)
            port = self._create_snatport_for_subnet(context, tenant_id,
                                                    subnet_id,
                                                    ip_address=None)
        network_info['port_id'] = port['id']
        network_info['snat_ip'] = port['fixed_ips'][0]['ip_address']
        msg = _("SNAT port: %s") % repr(port)
        LOG.info(msg)

    def _remove_snatport_for_subnet_if_not_used(self, context, tenant_id,
                                                subnet_id):
        pools = self._get_pools_on_subnet(context, tenant_id, subnet_id)
        if not pools:
            #No pools left on the old subnet.
            #We can remove the SNAT port/ipaddress
            self._remove_snatport_for_subnet(context, tenant_id, subnet_id)
            msg = _("Removing SNAT port for subnet %s "
                    "as this is the last pool using it...") % subnet_id
            LOG.info(msg)

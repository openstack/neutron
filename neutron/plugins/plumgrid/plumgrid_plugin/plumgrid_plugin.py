# Copyright 2013 PLUMgrid, Inc. All Rights Reserved.
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

"""
Neutron Plug-in for PLUMgrid Virtual Networking Infrastructure (VNI)
This plugin will forward authenticated REST API calls
to the PLUMgrid Network Management System called Director
"""

import netaddr
from oslo_config import cfg
from oslo_utils import importutils
from sqlalchemy.orm import exc as sa_exc

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import l3_db
from neutron.db import portbindings_db
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_db
from neutron.extensions import portbindings
from neutron.extensions import securitygroup as sec_grp
from neutron.i18n import _LI, _LW
from neutron.openstack.common import log as logging
from neutron.plugins.plumgrid.common import exceptions as plum_excep
from neutron.plugins.plumgrid.plumgrid_plugin import plugin_ver

LOG = logging.getLogger(__name__)

director_server_opts = [
    cfg.StrOpt('director_server', default='localhost',
               help=_("PLUMgrid Director server to connect to")),
    cfg.StrOpt('director_server_port', default='8080',
               help=_("PLUMgrid Director server port to connect to")),
    cfg.StrOpt('username', default='username',
               help=_("PLUMgrid Director admin username")),
    cfg.StrOpt('password', default='password', secret=True,
               help=_("PLUMgrid Director admin password")),
    cfg.IntOpt('servertimeout', default=5,
               help=_("PLUMgrid Director server timeout")),
    cfg.StrOpt('driver',
               default="neutron.plugins.plumgrid.drivers.plumlib.Plumlib",
               help=_("PLUMgrid Driver")), ]

cfg.CONF.register_opts(director_server_opts, "plumgriddirector")


class NeutronPluginPLUMgridV2(db_base_plugin_v2.NeutronDbPluginV2,
                              external_net_db.External_net_db_mixin,
                              l3_db.L3_NAT_db_mixin,
                              portbindings_db.PortBindingMixin,
                              securitygroups_db.SecurityGroupDbMixin):

    supported_extension_aliases = ["binding", "external-net", "provider",
                                   "quotas", "router", "security-group"]

    binding_view = "extension:port_binding:view"
    binding_set = "extension:port_binding:set"

    def __init__(self):
        LOG.info(_LI('Neutron PLUMgrid Director: Starting Plugin'))

        super(NeutronPluginPLUMgridV2, self).__init__()
        self.plumgrid_init()

        LOG.debug('Neutron PLUMgrid Director: Neutron server with '
                  'PLUMgrid Plugin has started')

    def plumgrid_init(self):
        """PLUMgrid initialization."""
        director_plumgrid = cfg.CONF.plumgriddirector.director_server
        director_port = cfg.CONF.plumgriddirector.director_server_port
        director_admin = cfg.CONF.plumgriddirector.username
        director_password = cfg.CONF.plumgriddirector.password
        timeout = cfg.CONF.plumgriddirector.servertimeout
        plum_driver = cfg.CONF.plumgriddirector.driver

        # PLUMgrid Director info validation
        LOG.info(_LI('Neutron PLUMgrid Director: %s'), director_plumgrid)
        self._plumlib = importutils.import_object(plum_driver)
        self._plumlib.director_conn(director_plumgrid, director_port, timeout,
                                    director_admin, director_password)

    def create_network(self, context, network):
        """Create Neutron network.

        Creates a PLUMgrid-based bridge.
        """

        LOG.debug('Neutron PLUMgrid Director: create_network() called')

        # Plugin DB - Network Create and validation
        tenant_id = self._get_tenant_id_for_create(context,
                                                   network["network"])
        self._network_admin_state(network)

        with context.session.begin(subtransactions=True):
            net_db = super(NeutronPluginPLUMgridV2,
                           self).create_network(context, network)
            # Propagate all L3 data into DB
            self._process_l3_create(context, net_db, network['network'])
            self._ensure_default_security_group(context, tenant_id)

            try:
                LOG.debug('PLUMgrid Library: create_network() called')
                self._plumlib.create_network(tenant_id, net_db, network)

            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

        # Return created network
        return net_db

    def update_network(self, context, net_id, network):
        """Update Neutron network.

        Updates a PLUMgrid-based bridge.
        """

        LOG.debug("Neutron PLUMgrid Director: update_network() called")
        self._network_admin_state(network)
        tenant_id = self._get_tenant_id_for_create(context, network["network"])

        with context.session.begin(subtransactions=True):
            # Plugin DB - Network Update
            net_db = super(
                NeutronPluginPLUMgridV2, self).update_network(context,
                                                              net_id, network)
            self._process_l3_update(context, net_db, network['network'])

            try:
                LOG.debug("PLUMgrid Library: update_network() called")
                self._plumlib.update_network(tenant_id, net_id)

            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

        # Return updated network
        return net_db

    def delete_network(self, context, net_id):
        """Delete Neutron network.

        Deletes a PLUMgrid-based bridge.
        """

        LOG.debug("Neutron PLUMgrid Director: delete_network() called")
        net_db = super(NeutronPluginPLUMgridV2,
                       self).get_network(context, net_id)

        with context.session.begin(subtransactions=True):
            self._process_l3_delete(context, net_id)
            # Plugin DB - Network Delete
            super(NeutronPluginPLUMgridV2, self).delete_network(context,
                                                                net_id)

            try:
                LOG.debug("PLUMgrid Library: update_network() called")
                self._plumlib.delete_network(net_db, net_id)

            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

    def create_port(self, context, port):
        """Create Neutron port.

        Creates a PLUMgrid-based port on the specific Virtual Network
        Function (VNF).
        """
        LOG.debug("Neutron PLUMgrid Director: create_port() called")

        # Port operations on PLUMgrid Director is an automatic operation
        # from the VIF driver operations in Nova.
        # It requires admin_state_up to be True

        port["port"]["admin_state_up"] = True
        port_data = port["port"]

        with context.session.begin(subtransactions=True):
            # Plugin DB - Port Create and Return port
            port_db = super(NeutronPluginPLUMgridV2, self).create_port(context,
                                                                       port)
            # Update port security
            port_data.update(port_db)

            self._ensure_default_security_group_on_port(context, port)

            port_data[sec_grp.SECURITYGROUPS] = (
                self._get_security_groups_on_port(context, port))

            self._process_port_create_security_group(
                context, port_db, port_data[sec_grp.SECURITYGROUPS])

            self._process_portbindings_create_and_update(context,
                                                         port_data, port_db)

            device_id = port_db["device_id"]
            if port_db["device_owner"] == constants.DEVICE_OWNER_ROUTER_GW:
                router_db = self._get_router(context, device_id)
            else:
                router_db = None

            try:
                LOG.debug("PLUMgrid Library: create_port() called")
                self._plumlib.create_port(port_db, router_db)

            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

        # Plugin DB - Port Create and Return port
        return self._port_viftype_binding(context, port_db)

    def update_port(self, context, port_id, port):
        """Update Neutron port.

        Updates a PLUMgrid-based port on the specific Virtual Network
        Function (VNF).
        """
        LOG.debug("Neutron PLUMgrid Director: update_port() called")

        with context.session.begin(subtransactions=True):
            # Plugin DB - Port Create and Return port
            port_db = super(NeutronPluginPLUMgridV2, self).update_port(
                context, port_id, port)
            device_id = port_db["device_id"]
            if port_db["device_owner"] == constants.DEVICE_OWNER_ROUTER_GW:
                router_db = self._get_router(context, device_id)
            else:
                router_db = None

            if (self._check_update_deletes_security_groups(port) or
                    self._check_update_has_security_groups(port)):
                self._delete_port_security_group_bindings(context,
                                                          port_db["id"])
                sg_ids = self._get_security_groups_on_port(context, port)
                self._process_port_create_security_group(context,
                                                         port_db,
                                                         sg_ids)

            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         port_db)

            try:
                LOG.debug("PLUMgrid Library: create_port() called")
                self._plumlib.update_port(port_db, router_db)

            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

        # Plugin DB - Port Update
        return self._port_viftype_binding(context, port_db)

    def delete_port(self, context, port_id, l3_port_check=True):
        """Delete Neutron port.

        Deletes a PLUMgrid-based port on the specific Virtual Network
        Function (VNF).
        """

        LOG.debug("Neutron PLUMgrid Director: delete_port() called")

        with context.session.begin(subtransactions=True):
            # Plugin DB - Port Create and Return port
            port_db = super(NeutronPluginPLUMgridV2,
                            self).get_port(context, port_id)
            router_ids = self.disassociate_floatingips(
                context, port_id, do_notify=False)
            super(NeutronPluginPLUMgridV2, self).delete_port(context, port_id)

            if port_db["device_owner"] == constants.DEVICE_OWNER_ROUTER_GW:
                device_id = port_db["device_id"]
                router_db = self._get_router(context, device_id)
            else:
                router_db = None
            try:
                LOG.debug("PLUMgrid Library: delete_port() called")
                self._plumlib.delete_port(port_db, router_db)

            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

        # now that we've left db transaction, we are safe to notify
        self.notify_routers_updated(context, router_ids)

    def get_port(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            port_db = super(NeutronPluginPLUMgridV2,
                            self).get_port(context, id, fields)

            self._port_viftype_binding(context, port_db)
        return self._fields(port_db, fields)

    def get_ports(self, context, filters=None, fields=None):
        with context.session.begin(subtransactions=True):
            ports_db = super(NeutronPluginPLUMgridV2,
                             self).get_ports(context, filters, fields)
            for port_db in ports_db:
                self._port_viftype_binding(context, port_db)
        return [self._fields(port, fields) for port in ports_db]

    def create_subnet(self, context, subnet):
        """Create Neutron subnet.

        Creates a PLUMgrid-based DHCP and NAT Virtual Network
        Functions (VNFs).
        """

        LOG.debug("Neutron PLUMgrid Director: create_subnet() called")

        with context.session.begin(subtransactions=True):
            # Plugin DB - Subnet Create
            net_db = super(NeutronPluginPLUMgridV2, self).get_network(
                context, subnet['subnet']['network_id'], fields=None)
            s = subnet['subnet']
            ipnet = netaddr.IPNetwork(s['cidr'])

            # PLUMgrid Director reserves the last IP address for GW
            # when is not defined
            if s['gateway_ip'] is attributes.ATTR_NOT_SPECIFIED:
                gw_ip = str(netaddr.IPAddress(ipnet.last - 1))
                subnet['subnet']['gateway_ip'] = gw_ip

            # PLUMgrid reserves the first IP
            if s['allocation_pools'] == attributes.ATTR_NOT_SPECIFIED:
                allocation_pool = self._allocate_pools_for_subnet(context, s)
                subnet['subnet']['allocation_pools'] = allocation_pool

            sub_db = super(NeutronPluginPLUMgridV2, self).create_subnet(
                context, subnet)

            try:
                LOG.debug("PLUMgrid Library: create_subnet() called")
                self._plumlib.create_subnet(sub_db, net_db, ipnet)
            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

        return sub_db

    def delete_subnet(self, context, subnet_id):
        """Delete subnet core Neutron API."""

        LOG.debug("Neutron PLUMgrid Director: delete_subnet() called")
        # Collecting subnet info
        sub_db = self._get_subnet(context, subnet_id)
        net_id = sub_db["network_id"]
        net_db = self.get_network(context, net_id)
        tenant_id = net_db["tenant_id"]

        with context.session.begin(subtransactions=True):
            # Plugin DB - Subnet Delete
            super(NeutronPluginPLUMgridV2, self).delete_subnet(
                context, subnet_id)
            try:
                LOG.debug("PLUMgrid Library: delete_subnet() called")
                self._plumlib.delete_subnet(tenant_id, net_db, net_id)
            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

    def update_subnet(self, context, subnet_id, subnet):
        """Update subnet core Neutron API."""

        LOG.debug("update_subnet() called")
        # Collecting subnet info
        orig_sub_db = self._get_subnet(context, subnet_id)

        with context.session.begin(subtransactions=True):
            # Plugin DB - Subnet Update
            new_sub_db = super(NeutronPluginPLUMgridV2,
                               self).update_subnet(context, subnet_id, subnet)
            ipnet = netaddr.IPNetwork(new_sub_db['cidr'])

            try:
                # PLUMgrid Server does not support updating resources yet
                LOG.debug("PLUMgrid Library: update_network() called")
                self._plumlib.update_subnet(orig_sub_db, new_sub_db, ipnet)

            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

        return new_sub_db

    def create_router(self, context, router):
        """
        Create router extension Neutron API
        """
        LOG.debug("Neutron PLUMgrid Director: create_router() called")

        tenant_id = self._get_tenant_id_for_create(context, router["router"])

        with context.session.begin(subtransactions=True):

            # Create router in DB
            router_db = super(NeutronPluginPLUMgridV2,
                              self).create_router(context, router)
            # Create router on the network controller
            try:
                # Add Router to VND
                LOG.debug("PLUMgrid Library: create_router() called")
                self._plumlib.create_router(tenant_id, router_db)
            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

        # Return created router
        return router_db

    def update_router(self, context, router_id, router):

        LOG.debug("Neutron PLUMgrid Director: update_router() called")

        with context.session.begin(subtransactions=True):
            router_db = super(NeutronPluginPLUMgridV2,
                              self).update_router(context, router_id, router)
            try:
                LOG.debug("PLUMgrid Library: update_router() called")
                self._plumlib.update_router(router_db, router_id)
            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

        # Return updated router
        return router_db

    def delete_router(self, context, router_id):
        LOG.debug("Neutron PLUMgrid Director: delete_router() called")

        with context.session.begin(subtransactions=True):
            orig_router = self._get_router(context, router_id)
            tenant_id = orig_router["tenant_id"]

            super(NeutronPluginPLUMgridV2, self).delete_router(context,
                                                               router_id)

            try:
                LOG.debug("PLUMgrid Library: delete_router() called")
                self._plumlib.delete_router(tenant_id, router_id)

            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

    def add_router_interface(self, context, router_id, interface_info):

        LOG.debug("Neutron PLUMgrid Director: "
                  "add_router_interface() called")
        with context.session.begin(subtransactions=True):
            # Validate args
            router_db = self._get_router(context, router_id)
            tenant_id = router_db['tenant_id']

            # Create interface in DB
            int_router = super(NeutronPluginPLUMgridV2,
                               self).add_router_interface(context,
                                                          router_id,
                                                          interface_info)
            port_db = self._get_port(context, int_router['port_id'])
            subnet_id = port_db["fixed_ips"][0]["subnet_id"]
            subnet_db = super(NeutronPluginPLUMgridV2,
                              self)._get_subnet(context, subnet_id)
            ipnet = netaddr.IPNetwork(subnet_db['cidr'])

            # Create interface on the network controller
            try:
                LOG.debug("PLUMgrid Library: add_router_interface() called")
                self._plumlib.add_router_interface(tenant_id, router_id,
                                                   port_db, ipnet)

            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

        return int_router

    def remove_router_interface(self, context, router_id, int_info):

        LOG.debug("Neutron PLUMgrid Director: remove_router_interface()"
                  " called")
        with context.session.begin(subtransactions=True):
            # Validate args
            router_db = self._get_router(context, router_id)
            tenant_id = router_db['tenant_id']
            if 'port_id' in int_info:
                port = self._get_port(context, int_info['port_id'])
                net_id = port['network_id']

            elif 'subnet_id' in int_info:
                subnet_id = int_info['subnet_id']
                subnet = self._get_subnet(context, subnet_id)
                net_id = subnet['network_id']

            # Remove router in DB
            del_int_router = super(NeutronPluginPLUMgridV2,
                                   self).remove_router_interface(context,
                                                                 router_id,
                                                                 int_info)

            try:
                LOG.debug("PLUMgrid Library: "
                          "remove_router_interface() called")
                self._plumlib.remove_router_interface(tenant_id,
                                                      net_id, router_id)

            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

        return del_int_router

    def create_floatingip(self, context, floatingip):
        LOG.debug("Neutron PLUMgrid Director: create_floatingip() called")

        with context.session.begin(subtransactions=True):

            floating_ip = super(NeutronPluginPLUMgridV2,
                                self).create_floatingip(context, floatingip)
            try:
                LOG.debug("PLUMgrid Library: create_floatingip() called")
                self._plumlib.create_floatingip(floating_ip)

            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

        return floating_ip

    def update_floatingip(self, context, id, floatingip):
        LOG.debug("Neutron PLUMgrid Director: update_floatingip() called")

        with context.session.begin(subtransactions=True):
            floating_ip_orig = super(NeutronPluginPLUMgridV2,
                                     self).get_floatingip(context, id)
            floating_ip = super(NeutronPluginPLUMgridV2,
                                self).update_floatingip(context, id,
                                                        floatingip)
            try:
                LOG.debug("PLUMgrid Library: update_floatingip() called")
                self._plumlib.update_floatingip(floating_ip_orig, floating_ip,
                                                id)

            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

        return floating_ip

    def delete_floatingip(self, context, id):
        LOG.debug("Neutron PLUMgrid Director: delete_floatingip() called")

        with context.session.begin(subtransactions=True):

            floating_ip_orig = super(NeutronPluginPLUMgridV2,
                                     self).get_floatingip(context, id)

            super(NeutronPluginPLUMgridV2, self).delete_floatingip(context, id)

            try:
                LOG.debug("PLUMgrid Library: delete_floatingip() called")
                self._plumlib.delete_floatingip(floating_ip_orig, id)

            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

    def disassociate_floatingips(self, context, port_id, do_notify=True):
        LOG.debug("Neutron PLUMgrid Director: disassociate_floatingips() "
                  "called")

        try:
            fip_qry = context.session.query(l3_db.FloatingIP)
            floating_ip = fip_qry.filter_by(fixed_port_id=port_id).one()

            LOG.debug("PLUMgrid Library: disassociate_floatingips()"
                      " called")
            self._plumlib.disassociate_floatingips(floating_ip, port_id)

        except sa_exc.NoResultFound:
            pass

        except Exception as err_message:
            raise plum_excep.PLUMgridException(err_msg=err_message)

        return super(NeutronPluginPLUMgridV2,
                     self).disassociate_floatingips(
                             context, port_id, do_notify=do_notify)

    def create_security_group(self, context, security_group, default_sg=False):
        """Create a security group

        Create a new security group, including the default security group
        """
        LOG.debug("Neutron PLUMgrid Director: create_security_group()"
                  " called")

        with context.session.begin(subtransactions=True):

            sg = security_group.get('security_group')

            tenant_id = self._get_tenant_id_for_create(context, sg)
            if not default_sg:
                self._ensure_default_security_group(context, tenant_id)

            sg_db = super(NeutronPluginPLUMgridV2,
                          self).create_security_group(context, security_group,
                                                      default_sg)
            try:
                LOG.debug("PLUMgrid Library: create_security_group()"
                          " called")
                self._plumlib.create_security_group(sg_db)

            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

        return sg_db

    def update_security_group(self, context, sg_id, security_group):
        """Update a security group

        Update security group name/description in Neutron and PLUMgrid
        platform
        """
        with context.session.begin(subtransactions=True):
            sg_db = (super(NeutronPluginPLUMgridV2,
                           self).update_security_group(context,
                                                       sg_id,
                                                       security_group))
            if ('name' in security_group['security_group'] and
                sg_db['name'] != 'default'):
                try:
                    LOG.debug("PLUMgrid Library: update_security_group()"
                              " called")
                    self._plumlib.update_security_group(sg_db)

                except Exception as err_message:
                    raise plum_excep.PLUMgridException(err_msg=err_message)
            return sg_db

    def delete_security_group(self, context, sg_id):
        """Delete a security group

        Delete security group from Neutron and PLUMgrid Platform

        :param sg_id: security group ID of the rule to be removed
        """
        with context.session.begin(subtransactions=True):

            sg = super(NeutronPluginPLUMgridV2, self).get_security_group(
                context, sg_id)
            if not sg:
                raise sec_grp.SecurityGroupNotFound(id=sg_id)

            if sg['name'] == 'default' and not context.is_admin:
                raise sec_grp.SecurityGroupCannotRemoveDefault()

            sec_grp_ip = sg['id']
            filters = {'security_group_id': [sec_grp_ip]}
            if super(NeutronPluginPLUMgridV2,
                     self)._get_port_security_group_bindings(context,
                                                             filters):
                raise sec_grp.SecurityGroupInUse(id=sec_grp_ip)

            sec_db = super(NeutronPluginPLUMgridV2,
                           self).delete_security_group(context, sg_id)
            try:
                LOG.debug("PLUMgrid Library: delete_security_group()"
                          " called")
                self._plumlib.delete_security_group(sg)

            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

            return sec_db

    def create_security_group_rule(self, context, security_group_rule):
        """Create a security group rule

        Create a security group rule in Neutron and PLUMgrid Platform
        """
        LOG.debug("Neutron PLUMgrid Director: create_security_group_rule()"
                  " called")
        bulk_rule = {'security_group_rules': [security_group_rule]}
        return self.create_security_group_rule_bulk(context, bulk_rule)[0]

    def create_security_group_rule_bulk(self, context, security_group_rule):
        """Create security group rules

        Create security group rules in Neutron and PLUMgrid Platform

        :param security_group_rule: list of rules to create
        """
        sg_rules = security_group_rule.get('security_group_rules')

        with context.session.begin(subtransactions=True):
            sg_id = super(NeutronPluginPLUMgridV2,
                          self)._validate_security_group_rules(
                          context, security_group_rule)

            # Check to make sure security group exists
            security_group = super(NeutronPluginPLUMgridV2,
                                   self).get_security_group(context,
                                                            sg_id)

            if not security_group:
                raise sec_grp.SecurityGroupNotFound(id=sg_id)

            # Check for duplicate rules
            self._check_for_duplicate_rules(context, sg_rules)

            sec_db = (super(NeutronPluginPLUMgridV2,
                            self).create_security_group_rule_bulk_native(
                            context, security_group_rule))
            try:
                LOG.debug("PLUMgrid Library: create_security_"
                          "group_rule_bulk() called")
                self._plumlib.create_security_group_rule_bulk(sec_db)

            except Exception as err_message:
                raise plum_excep.PLUMgridException(err_msg=err_message)

            return sec_db

    def delete_security_group_rule(self, context, sgr_id):
        """Delete a security group rule

        Delete a security group rule in Neutron and PLUMgrid Platform
        """

        LOG.debug("Neutron PLUMgrid Director: delete_security_group_rule()"
                  " called")

        sgr = (super(NeutronPluginPLUMgridV2,
                     self).get_security_group_rule(context, sgr_id))

        if not sgr:
            raise sec_grp.SecurityGroupRuleNotFound(id=sgr_id)

        super(NeutronPluginPLUMgridV2,
              self).delete_security_group_rule(context, sgr_id)
        try:
            LOG.debug("PLUMgrid Library: delete_security_"
                      "group_rule() called")
            self._plumlib.delete_security_group_rule(sgr)

        except Exception as err_message:
            raise plum_excep.PLUMgridException(err_msg=err_message)

    #
    # Internal PLUMgrid Functions
    #

    def _get_plugin_version(self):
        return plugin_ver.VERSION

    def _port_viftype_binding(self, context, port):
        port[portbindings.VIF_TYPE] = portbindings.VIF_TYPE_IOVISOR
        port[portbindings.VIF_DETAILS] = {
            # TODO(rkukura): Replace with new VIF security details
            portbindings.CAP_PORT_FILTER:
            'security-group' in self.supported_extension_aliases}
        return port

    def _network_admin_state(self, network):
        if network["network"].get("admin_state_up") is False:
            LOG.warning(_LW("Networks with admin_state_up=False are not "
                            "supported by PLUMgrid plugin yet."))
        return network

    def _allocate_pools_for_subnet(self, context, subnet):
        """Create IP allocation pools for a given subnet

        Pools are defined by the 'allocation_pools' attribute,
        a list of dict objects with 'start' and 'end' keys for
        defining the pool range.
        Modified from Neutron DB based class

        """

        pools = []
        # Auto allocate the pool around gateway_ip
        net = netaddr.IPNetwork(subnet['cidr'])
        boundary = int(netaddr.IPAddress(subnet['gateway_ip'] or net.last))
        potential_dhcp_ip = int(net.first + 1)
        if boundary == potential_dhcp_ip:
            first_ip = net.first + 3
            boundary = net.first + 2
        else:
            first_ip = net.first + 2
        last_ip = net.last - 1
        # Use the gw_ip to find a point for splitting allocation pools
        # for this subnet
        split_ip = min(max(boundary, net.first), net.last)
        if split_ip > first_ip:
            pools.append({'start': str(netaddr.IPAddress(first_ip)),
                          'end': str(netaddr.IPAddress(split_ip - 1))})
        if split_ip < last_ip:
            pools.append({'start': str(netaddr.IPAddress(split_ip + 1)),
                          'end': str(netaddr.IPAddress(last_ip))})
            # return auto-generated pools
        # no need to check for their validity
        return pools

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Contrail Systems, Inc.
#

"""
.. attention:: Fix the license string
"""

import logging
import ConfigParser
from pprint import pformat

from neutron.manager import NeutronManager
from neutron.common import exceptions as exc
from neutron.db import db_base_plugin_v2
from neutron.db import portbindings_base
from neutron.db import l3_db
from neutron.extensions import l3, securitygroup, vpcroutetable
from neutron.extensions import portbindings
from neutron.openstack.common import log as logging

from oslo.config import cfg
from httplib2 import Http
import re
import string
import sys
import cgitb

import ctdb.config_db

LOG = logging.getLogger(__name__)

vnc_opts = [
    cfg.StrOpt('api_server_ip', default='127.0.0.1'),
    cfg.StrOpt('api_server_port', default='8082'),
]


def _read_cfg(cfg_parser, section, option, default):
        try:
            val = cfg_parser.get(section, option)
        except (AttributeError,
                ConfigParser.NoOptionError,
                ConfigParser.NoSectionError):
            val = default

        return val
#end _read_cfg


def _read_cfg_boolean(cfg_parser, section, option, default):
        try:
            val = cfg_parser.getboolean(section, option)
        except (AttributeError, ValueError,
                ConfigParser.NoOptionError,
                ConfigParser.NoSectionError):
            val = default

        return val
#end _read_cfg


#TODO define ABC PluginBase for ipam and policy and derive mixin from them
class ContrailPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                     securitygroup.SecurityGroupPluginBase,
                     portbindings_base.PortBindingBaseMixin,
                     l3_db.L3_NAT_db_mixin):
    """
    .. attention::  TODO remove db. ref and replace ctdb. with db.
    """

    # agent extension is added to avoid return 404 for get_agents
    supported_extension_aliases = ["ipam", "policy", "security-group",
                                   "router", "route-table", "port-security",
                                   "binding", "agent"]
    _cfgdb = None
    _args = None
    _tenant_id_dict = {}
    _tenant_name_dict = {}

    @classmethod
    def _parse_class_args(cls, cfg_parser):
        cfg_parser.read("/etc/neutron/plugins/juniper/contrail/ContrailPlugin.ini")
        cls._multi_tenancy = _read_cfg_boolean(cfg_parser, 'APISERVER',
                                               'multi_tenancy', False)
        cls._admin_token = _read_cfg(cfg_parser, 'KEYSTONE', 'admin_token', '')
        cls._auth_url = _read_cfg(cfg_parser, 'KEYSTONE', 'auth_url', '')
        cls._admin_user = _read_cfg(cfg_parser, 'KEYSTONE', 'admin_user',
                                    'user1')
        cls._admin_password = _read_cfg(cfg_parser, 'KEYSTONE',
                                        'admin_password', 'password1')
        cls._admin_tenant_name = _read_cfg(cfg_parser, 'KEYSTONE',
                                           'admin_tenant_name',
                                           'default-domain')
        cls._tenants_api = '%s/tenants' % (cls._auth_url)
        pass
    #end _parse_class_args

    @classmethod
    def _connect_to_db(cls):
        """
        Many instantiations of plugin (base + extensions) but need to have
    only one config db conn (else error from ifmap-server)
    """
        cls._cfgdb_map = {}
        if cls._cfgdb is None:
            sip = cfg.CONF.APISERVER.api_server_ip
            sport = cfg.CONF.APISERVER.api_server_port
            # Initialize connection to DB and add default entries
            cls._cfgdb = ctdb.config_db.DBInterface(cls._admin_user,
                                                    cls._admin_password,
                                                    cls._admin_tenant_name,
                                                    sip, sport)
            cls._cfgdb.manager = cls
    #end _connect_to_db

    @classmethod
    def _get_user_cfgdb(cls, context):
        if not cls._multi_tenancy:
            return cls._cfgdb
        user_id = context.user_id
        role = string.join(context.roles, ",")
        if not user_id in cls._cfgdb_map:
            cls._cfgdb_map[user_id] = ctdb.config_db.DBInterface(
                cls._admin_user, cls._admin_password, cls._admin_tenant_name,
                cfg.CONF.APISERVER.api_server_ip,
                cfg.CONF.APISERVER.api_server_port,
                user_info={'user_id': user_id, 'role': role})
            cls._cfgdb_map[user_id].manager = cls

        return cls._cfgdb_map[user_id]
    #end _get_cfgdb

    @classmethod
    def _tenant_list_from_keystone(cls):
        # get all tenants
        hdrs = {'X-Auth-Token': cls._admin_token,
                'Content-Type': 'application/json'}
        try:
            rsp, content = Http().request(cls._tenants_api,
                                          method="GET", headers=hdrs)
            if rsp.status != 200:
                return
        except:
            return

        # transform needed for python compatibility
        content = re.sub('true', 'True', content)
        content = re.sub('null', 'None', content)
        content = eval(content)

        # bail if response is unexpected
        if 'tenants' not in content:
            return

        # create a dictionary for id->name and name->id mapping
        for tenant in content['tenants']:
            print 'Adding tenant %s:%s to cache' % (tenant['name'],
                                                    tenant['id'])
            cls._tenant_id_dict[tenant['id']] = tenant['name']
            cls._tenant_name_dict[tenant['name']] = tenant['id']
    #end _tenant_list_from_keystone

    def update_security_group(self, context, id, security_group):
        pass

    def __init__(self):
        cfg.CONF.register_opts(vnc_opts, 'APISERVER')

        cfg_parser = ConfigParser.ConfigParser()
        ContrailPlugin._parse_class_args(cfg_parser)

        ContrailPlugin._connect_to_db()
        self._cfgdb = ContrailPlugin._cfgdb

        ContrailPlugin._tenant_list_from_keystone()
        self.base_binding_dict = self._get_base_binding_dict()
        portbindings_base.register_port_dict_function()
    #end __init__

    def _get_base_binding_dict(self):
        binding = {
            portbindings.VIF_TYPE: portbindings.VIF_TYPE_VROUTER,
            portbindings.CAPABILITIES: {
                portbindings.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}}
        return binding

    @classmethod
    def tenant_id_to_name(cls, id):
        # bail if we never built the list successfully
        if len(cls._tenant_id_dict) == 0:
            return id
        # check cache
        if id in cls._tenant_id_dict:
            return cls._tenant_id_dict[id]
        # otherwise refresh
        cls._tenant_list_from_keystone()
        # second time's a charm?
        return cls._tenant_id_dict[id] if id in cls._tenant_id_dict else id
    #end tenant_id_to_name

    @classmethod
    def tenant_name_to_id(cls, name):
        # bail if we never built the list successfully
        if len(cls._tenant_name_dict) == 0:
            return name
        # check cache
        if name in cls._tenant_name_dict:
            return cls._tenant_name_dict[name]
        # otherwise refresh
        cls._tenant_list_from_keystone()
        # second time's a charm?
        if name in cls._tenant_name_dict:
            return cls._tenant_name_dict[name]
        else:
            return name
    #end tenant_name_to_id

    # Return empty list of agents.
    def get_agents(self, context, filters=None, fields=None):
        agents = []
        return agents;

    # Network API handlers
    def create_network(self, context, network):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            net_info = cfgdb.network_create(network['network'])

            # verify transformation is conforming to api
            net_dict = self._make_network_dict(net_info['q_api_data'])

            net_dict.update(net_info['q_extra_data'])

            LOG.debug("create_network(): " + pformat(net_dict) + "\n")
            return net_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end create_network

    def get_network(self, context, id, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            net_info = cfgdb.network_read(id, fields)

            # verify transformation is conforming to api
            if not fields:
                # should return all fields
                net_dict = self._make_network_dict(net_info['q_api_data'],
                                                   fields)
                net_dict.update(net_info['q_extra_data'])
            else:
                net_dict = net_info['q_api_data']

            LOG.debug("get_network(): " + pformat(net_dict))
            return self._fields(net_dict, fields)
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_network

    def update_network(self, context, net_id, network):
        """
        Updates the attributes of a particular Virtual Network.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            net_info = cfgdb.network_update(net_id, network['network'])

            # verify transformation is conforming to api
            net_dict = self._make_network_dict(net_info['q_api_data'])

            net_dict.update(net_info['q_extra_data'])

            LOG.debug("update_network(): " + pformat(net_dict))
            return net_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end update_network

    def delete_network(self, context, net_id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            cfgdb.network_delete(net_id)
            LOG.debug("delete_network(): " + pformat(net_id))
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end delete_network

    def get_networks(self, context, filters=None, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            nets_info = cfgdb.network_list(context, filters)

            nets_dicts = []
            for n_info in nets_info:
                # verify transformation is conforming to api
                n_dict = self._make_network_dict(n_info['q_api_data'], fields)

                n_dict.update(n_info['q_extra_data'])
                nets_dicts.append(n_dict)

            LOG.debug(
                "get_networks(): filters: " + pformat(filters) + " data: "
                + pformat(nets_dicts))
            return nets_dicts
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_networks

    def get_networks_count(self, context, filters=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            nets_count = cfgdb.network_count(filters)
            LOG.debug("get_networks_count(): " + str(nets_count))
            return nets_count
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_networks_count

    # Subnet API handlers
    def create_subnet(self, context, subnet):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            subnet_info = cfgdb.subnet_create(subnet['subnet'])

            # verify transformation is conforming to api
            subnet_dict = self._make_subnet_dict(subnet_info['q_api_data'])

            subnet_dict.update(subnet_info['q_extra_data'])

            LOG.debug("create_subnet(): " + pformat(subnet_dict))
            return subnet_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end create_subnet

    def get_subnet(self, context, subnet_id, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            subnet_info = cfgdb.subnet_read(subnet_id)

            # verify transformation is conforming to api
            subnet_dict = self._make_subnet_dict(subnet_info['q_api_data'],
                                                 fields)

            subnet_dict.update(subnet_info['q_extra_data'])

            LOG.debug("get_subnet(): " + pformat(subnet_dict))
            return self._fields(subnet_dict, fields)
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_subnet

    def update_subnet(self, context, subnet_id, subnet):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            subnet_info = cfgdb.subnet_update(subnet_id, subnet['subnet'])

            # verify transformation is conforming to api
            subnet_dict = self._make_subnet_dict(subnet_info['q_api_data'])

            subnet_dict.update(subnet_info['q_extra_data'])

            LOG.debug("update_subnet(): " + pformat(subnet_dict))
            return subnet_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end update_subnet

    def delete_subnet(self, context, subnet_id):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            cfgdb.subnet_delete(subnet_id)

            LOG.debug("delete_subnet(): " + pformat(subnet_id))
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end delete_subnet

    def get_subnets(self, context, filters=None, fields=None):
        """
        Called from neutron API -> get_<resource>
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            subnets_info = cfgdb.subnets_list(filters)

            subnets_dicts = []
            for sn_info in subnets_info:
                # verify transformation is conforming to api
                sn_dict = self._make_subnet_dict(sn_info['q_api_data'], fields)

                sn_dict.update(sn_info['q_extra_data'])
                subnets_dicts.append(sn_dict)

            LOG.debug(
                "get_subnets(): filters: " + pformat(filters) + " data: "
                + pformat(subnets_dicts))
            return subnets_dicts
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_subnets

    def get_subnets_count(self, context, filters=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            subnets_count = cfgdb.subnets_count(filters)
            LOG.debug("get_subnets_count(): " + str(subnets_count))
            return subnets_count
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_subnets_count

    # Ipam API handlers
    def create_ipam(self, context, ipam):
        """
        Creates a new IPAM, and assigns it
        a symbolic name.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            ipam_info = cfgdb.ipam_create(ipam['ipam'])

            # TODO add this in extension
            ##verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            ipam_dict = ipam_info['q_api_data']
            ipam_dict.update(ipam_info['q_extra_data'])

            LOG.debug("create_ipam(): " + pformat(ipam_dict))
            return ipam_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end create_ipam

    def get_ipam(self, context, id, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            ipam_info = cfgdb.ipam_read(id)

            # TODO add this in extension
            ## verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            ipam_dict = ipam_info['q_api_data']
            ipam_dict.update(ipam_info['q_extra_data'])

            LOG.debug("get_ipam(): " + pformat(ipam_dict))
            return ipam_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_ipam

    def update_ipam(self, context, id, ipam):
        """
        Updates the attributes of a particular IPAM.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            ipam_info = cfgdb.ipam_update(id, ipam)

            # TODO add this in extension
            ## verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            ipam_dict = ipam_info['q_api_data']
            ipam_dict.update(ipam_info['q_extra_data'])

            LOG.debug("update_ipam(): " + pformat(ipam_dict))
            return ipam_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end update_ipam

    def delete_ipam(self, context, ipam_id):
        """
        Deletes the ipam with the specified identifier
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            cfgdb.ipam_delete(ipam_id)

            LOG.debug("delete_ipam(): " + pformat(ipam_id))
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end delete_ipam

    def get_ipams(self, context, filters=None, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            ipams_info = cfgdb.ipam_list(filters)

            ipams_dicts = []
            for ipam_info in ipams_info:
                # TODO add this in extension
                # verify transformation is conforming to api
                #ipam_dict = self._make_ipam_dict(ipam_info)
                ipam_dict = ipam_info['q_api_data']
                ipam_dict.update(ipam_info['q_extra_data'])
                ipams_dicts.append(ipam_dict)

            LOG.debug("get_ipams(): " + pformat(ipams_dicts))
            return ipams_dicts
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_ipams

    def get_ipams_count(self, context, filters=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            ipams_count = cfgdb.ipams_count(filters)
            LOG.debug("get_ipams_count(): " + str(ipams_count))
            return ipams_count
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_ipams_count

    # Policy API handlers
    def create_policy(self, context, policy):
        """
        Creates a new Policy, and assigns it
        a symbolic name.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            policy_info = cfgdb.policy_create(policy['policy'])

            # TODO add this in extension
            ##verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            policy_dict = policy_info['q_api_data']
            policy_dict.update(policy_info['q_extra_data'])

            LOG.debug("create_policy(): " + pformat(policy_dict))
            return policy_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end create_policy

    def get_policy(self, context, id, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            policy_info = cfgdb.policy_read(id)

            # TODO add this in extension
            ## verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            policy_dict = policy_info['q_api_data']
            policy_dict.update(policy_info['q_extra_data'])

            LOG.debug("get_policy(): " + pformat(policy_dict))
            return policy_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_policy

    def update_policy(self, context, id, policy):
        """
        Updates the attributes of a particular Policy.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            policy_info = cfgdb.policy_update(id, policy)

            # TODO add this in extension
            ## verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            policy_dict = policy_info['q_api_data']
            policy_dict.update(policy_info['q_extra_data'])

            LOG.debug("update_policy(): " + pformat(policy_dict))
            return policy_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end update_policy

    def delete_policy(self, context, policy_id):
        """
        Deletes the Policy with the specified identifier
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            cfgdb.policy_delete(policy_id)

            LOG.debug("delete_policy(): " + pformat(policy_id))
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end delete_policy

    def get_policys(self, context, filters=None, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            policys_info = cfgdb.policy_list(filters)

            policys_dicts = []
            for policy_info in policys_info:
                # TODO add this in extension
                # verify transformation is conforming to api
                #ipam_dict = self._make_ipam_dict(ipam_info)
                policy_dict = policy_info['q_api_data']
                policy_dict.update(policy_info['q_extra_data'])
                policys_dicts.append(policy_dict)

            LOG.debug("get_policys(): " + pformat(policys_dicts))
            return policys_dicts
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_policys

    def get_policy_count(self, context, filters=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            policy_count = cfgdb.policy_count(filters)
            LOG.debug("get_policy_count(): " + str(policy_count))
            return policy_count
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_policy_count

    def _make_router_dict(self, router, fields=None,
                          process_extensions=True):
        res = {'id': router['id'],
               'name': router['name'],
               'tenant_id': router['tenant_id'],
               'admin_state_up': router['admin_state_up'],
               'status': router['status'],
               'external_gateway_info': None,
               'gw_port_id': router['gw_port_id']}
        if router['gw_port_id']:
            nw_id = router['gw_port_id']['network_id']
            res['external_gateway_info'] = {'network_id': nw_id}
        # NOTE(salv-orlando): The following assumes this mixin is used in a
        # class inheriting from CommonDbMixin, which is true for all existing
        # plugins.
        if process_extensions:
            self._apply_dict_extend_functions(
                l3.ROUTERS, res, router)
        return self._fields(res, fields)

    # Router API handlers
    def create_router(self, context, router):
        """
        Creates a new Logical Router, and assigns it
        a symbolic name.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            router_info = cfgdb.router_create(router['router'])

            # verify transformation is conforming to api
            router_dict = self._make_router_dict(router_info['q_api_data'])

            router_dict.update(router_info['q_extra_data'])

            LOG.debug("create_router(): " + pformat(router_dict) + "\n")
            return router_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end create_router

    def get_router(self, context, id, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            router_info = cfgdb.router_read(id, fields)

            # verify transformation is conforming to api
            if not fields:
                # should return all fields
                router_dict = self._make_router_dict(router_info['q_api_data'],
                                                     fields)
                router_dict.update(router_info['q_extra_data'])
            else:
                router_dict = router_info['q_api_data']

            LOG.debug("get_router(): " + pformat(router_dict))
            return self._fields(router_dict, fields)
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_router

    def update_router(self, context, rtr_id, router):
        """
        Updates the attributes of a particular Logical Router.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            router_info = cfgdb.router_update(rtr_id, router['router'])

            # verify transformation is conforming to api
            router_dict = self._make_router_dict(router_info['q_api_data'])

            router_dict.update(router_info['q_extra_data'])

            LOG.debug("update_router(): " + pformat(router_dict))
            return router_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end update_network

    def delete_router(self, context, rtr_id):
        """
        Deletes the network with the specified router identifier
        belonging to the specified tenant.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            cfgdb.router_delete(rtr_id)
            LOG.debug("delete_router(): " + pformat(rtr_id))
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end delete_network

    def get_routers(self, context, filters=None, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            rtrs_info = cfgdb.router_list(filters)

            rtrs_dicts = []
            for r_info in rtrs_info:
                # verify transformation is conforming to api
                r_dict = self._make_router_dict(r_info['q_api_data'], fields)

                r_dict.update(r_info['q_extra_data'])
                rtrs_dicts.append(r_dict)

            LOG.debug(
                "get_routers(): filters: " + pformat(filters) + " data: "
                + pformat(rtrs_dicts))
            return rtrs_dicts
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_networks

    def get_routers_count(self, context, filters=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            rtrs_count = cfgdb.router_count(filters)
            LOG.debug("get_routers_count(): " + str(rtrs_count))
            return rtrs_count
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_networks_count

    def add_router_interface(self, context, router_id, interface_info):
        if not interface_info:
            msg = _("Either subnet_id or port_id must be specified")
            raise exc.BadRequest(resource='router', msg=msg)

        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            if 'port_id' in interface_info:
                if 'subnet_id' in interface_info:
                    msg = _("Cannot specify both subnet-id and port-id")
                    raise exc.BadRequest(resource='router', msg=msg)

                port_id = interface_info['port_id']
                return cfgdb.add_router_interface(router_id, port_id=port_id)
            elif 'subnet_id' in interface_info:
                subnet_id = interface_info['subnet_id']
                return cfgdb.add_router_interface(router_id,
                                                  subnet_id=subnet_id)
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    # end add_router_interface

    def remove_router_interface(self, context, router_id, interface_info):
        if not interface_info:
            msg = _("Either subnet_id or port_id must be specified")
            raise exc.BadRequest(resource='router', msg=msg)
        
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            if 'port_id' in interface_info:
                port_id = interface_info['port_id']
                return cfgdb.remove_router_interface(router_id, port_id=port_id)
            elif 'subnet_id' in interface_info:
                subnet_id = interface_info['subnet_id']
                return cfgdb.remove_router_interface(router_id, subnet_id=subnet_id)
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    # end remove_router_interface
    
    # Floating IP API handlers
    def _make_floatingip_dict(self, floatingip, fields=None):
        res = {'id': floatingip['id'],
               'tenant_id': floatingip['tenant_id'],
               'floating_ip_address': floatingip['floating_ip_address'],
               'floating_network_id': floatingip['floating_network_id'],
               'router_id': floatingip['router_id'],
               'port_id': floatingip['fixed_port_id'],
               'fixed_ip_address': floatingip['fixed_ip_address']}
        return self._fields(res, fields)

    def create_floatingip(self, context, floatingip):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            fip_info = cfgdb.floatingip_create(floatingip['floatingip'])

            # verify transformation is conforming to api
            fip_dict = self._make_floatingip_dict(fip_info['q_api_data'])

            fip_dict.update(fip_info['q_extra_data'])

            LOG.debug("create_floatingip(): " + pformat(fip_dict))
            return fip_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end create_floatingip

    def update_floatingip(self, context, fip_id, floatingip):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            fip_info = cfgdb.floatingip_update(fip_id,
                                               floatingip['floatingip'])

            # verify transformation is conforming to api
            fip_dict = self._make_floatingip_dict(fip_info['q_api_data'])

            fip_dict.update(fip_info['q_extra_data'])

            LOG.debug("update_floatingip(): " + pformat(fip_dict))
            return fip_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end update_floatingip

    def get_floatingip(self, context, id, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            fip_info = cfgdb.floatingip_read(id)

            # verify transformation is conforming to api
            fip_dict = self._make_floatingip_dict(fip_info['q_api_data'])

            fip_dict.update(fip_info['q_extra_data'])

            LOG.debug("get_floatingip(): " + pformat(fip_dict))
            return fip_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_floatingip

    def delete_floatingip(self, context, fip_id):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            cfgdb.floatingip_delete(fip_id)
            LOG.debug("delete_floating(): " + pformat(fip_id))
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end delete_floatingip

    def get_floatingips(self, context, filters=None, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            fips_info = cfgdb.floatingip_list(filters)

            fips_dicts = []
            for fip_info in fips_info:
                # verify transformation is conforming to api
                fip_dict = self._make_floatingip_dict(fip_info['q_api_data'])

                fip_dict.update(fip_info['q_extra_data'])
                fips_dicts.append(fip_dict)

            LOG.debug("get_floatingips(): " + pformat(fips_dicts))
            return fips_dicts
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_floatingips

    def get_floatingips_count(self, context, filters=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            floatingips_count = cfgdb.floatingip_count(filters)
            LOG.debug("get_floatingips_count(): " + str(floatingips_count))
            return floatingips_count
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_floatingips_count

    # Port API handlers
    def create_port(self, context, port):
        """
        Creates a port on the specified Virtual Network.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            port_info = cfgdb.port_create(port['port'])

            # verify transformation is conforming to api
            port_dict = self._make_port_dict(port_info['q_api_data'])
            self._process_portbindings_create_and_update(context,
                                                     port['port'],
                                                     port_dict)

            port_dict.update(port_info['q_extra_data'])

            LOG.debug("create_port(): " + pformat(port_dict))
            return port_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end create_port

    def get_port(self, context, port_id, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            port_info = cfgdb.port_read(port_id)

            # verify transformation is conforming to api
            port_dict = self._make_port_dict(port_info['q_api_data'], fields)
            self._process_portbindings_create_and_update(context,
                                                     port_info,
                                                     port_dict)

            port_dict.update(port_info['q_extra_data'])

            LOG.debug("get_port(): " + pformat(port_dict))
            return self._fields(port_dict, fields)
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_port

    def update_port(self, context, port_id, port):
        """
        Updates the attributes of a port on the specified Virtual Network.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            port_info = cfgdb.port_update(port_id, port['port'])

            # verify transformation is conforming to api
            port_dict = self._make_port_dict(port_info['q_api_data'])
            self._process_portbindings_create_and_update(context,
                                                     port['port'],
                                                     port_info)

            port_dict.update(port_info['q_extra_data'])

            LOG.debug("update_port(): " + pformat(port_dict))
            return port_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end update_port

    def delete_port(self, context, port_id):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface is first un-plugged and then the port
        is deleted.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            cfgdb.port_delete(port_id)
            LOG.debug("delete_port(): " + pformat(port_id))
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end delete_port

    def get_ports(self, context, filters=None, fields=None):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            ports_info = cfgdb.port_list(context, filters)

            ports_dicts = []
            for p_info in ports_info:
                # verify transformation is conforming to api
                p_dict = self._make_port_dict(p_info['q_api_data'], fields)
                self._process_portbindings_create_and_update(context,
                                                         p_info,
                                                         p_dict)

                p_dict.update(p_info['q_extra_data'])
                ports_dicts.append(p_dict)

            LOG.debug(
                "get_ports(): filter: " + pformat(filters) + 'data: '
                + pformat(ports_dicts))
            return ports_dicts
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_ports

    def get_ports_count(self, context, filters=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            ports_count = cfgdb.port_count(filters)
            LOG.debug("get_ports_count(): " + str(ports_count))
            return ports_count
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
    #end get_ports_count

    def plug_interface(self, tenant_id, net_id, port_id, remote_interface_id):
        """
        Attaches a remote interface to the specified port on the
        specified Virtual Network.
        """
        port = self._get_port(tenant_id, net_id, port_id)
        # Validate attachment
        self._validate_attachment(tenant_id, net_id, port_id,
                                  remote_interface_id)
        if port['interface_id']:
            raise exc.PortInUse(net_id=net_id, port_id=port_id,
                                att_id=port['interface_id'])
        db.port_set_attachment(port_id, net_id, remote_interface_id)

    def unplug_interface(self, tenant_id, net_id, port_id):
        """
        Detaches a remote interface from the specified port on the
        specified Virtual Network.
        """
        self._get_port(tenant_id, net_id, port_id)
        db.port_unset_attachment(port_id, net_id)

    # VPC route table handlers
    def _make_route_table_routes_dict(self, route_table_route, fields=None):
        res = {'prefix': route_table_route['prefix'],
               'next_hop': route_table_route['next_hop']}

        return self._fields(res, fields)

    def _make_route_table_dict(self, route_table, fields=None):
        res = {'id': route_table['id'],
               'name': route_table['name'],
               'fq_name': route_table['fq_name'],
               'tenant_id': route_table['tenant_id']}
        if route_table['routes']:
            res['routes'] = [self._make_route_table_routes_dict(r)
                             for r in route_table['routes']['route']]
        else:
            res['routes'] = {}
        return self._fields(res, fields)

    def create_route_table(self, context, route_table):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            rt_info = cfgdb.route_table_create(
                          route_table['route_table'])

            # verify transformation is conforming to api
            rt_dict = self._make_route_table_dict(rt_info['q_api_data'])
            rt_dict.update(rt_info['q_extra_data'])
            LOG.debug("create_route_table(): " + pformat(rt_dict))
            return rt_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def update_route_table(self, context, id, route_table):
        """
        Updates the attributes of a particular route table.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            rt_info = cfgdb.route_table_update(id, route_table['route_table'])

            rt_dict = self._make_route_table_dict(rt_info['q_api_data'])
            rt_dict.update(rt_info['q_extra_data'])
            LOG.debug("create_route_table(): " + pformat(rt_dict))
            return rt_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def delete_route_table(self, context, id):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            cfgdb.route_table_delete(id)
            LOG.debug("delete_route_table(): " + pformat(id))
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_route_tables(self, context, filters=None, fields=None,
                         sorts=None, limit=None, marker=None,
                         page_reverse=False):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            route_tables_info = cfgdb.route_table_list(context, filters)

            route_tables_dicts = []
            for rt_info in route_tables_info:
                # verify transformation is conforming to api
                rt_dict = self._make_route_table_dict(rt_info['q_api_data'],
                                                      fields)

                rt_dict.update(rt_info['q_extra_data'])
                route_tables_dicts.append(rt_dict)

            LOG.debug(
                "get_route_tables(): filter: " + pformat(filters)
                + 'data: ' + pformat(route_tables_dicts))
            return route_tables_dicts
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_route_table(self, context, id, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            rt_info = cfgdb.route_table_read(id)

            # verify transformation is conforming to api
            rt_dict = self._make_route_table_dict(rt_info['q_api_data'],
                                                  fields)

            rt_dict.update(rt_info['q_extra_data'])

            LOG.debug("get_route_table(): " + pformat(rt_dict))
            return self._fields(rt_dict, fields)
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    # VPC route table svc instance handlers
    def _make_svc_instance_dict(self, svc_instance, fields=None):
        res = {'id': svc_instance['id'],
               'name': svc_instance['name'],
               'tenant_id': svc_instance['tenant_id']}
        if svc_instance['internal_net']:
            res['internal_net'] = svc_instance['internal_net']
        if svc_instance['external_net']:
            res['external_net'] = svc_instance['external_net']
        return self._fields(res, fields)

    def create_nat_instance(self, context, nat_instance):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            si_info = cfgdb.svc_instance_create(
                          nat_instance['nat_instance'])

            # verify transformation is conforming to api
            si_dict = self._make_svc_instance_dict(si_info['q_api_data'])

            si_dict.update(si_info['q_extra_data'])

            LOG.debug("create_nat_instance(): " + pformat(si_dict))
            return si_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def delete_nat_instance(self, context, id):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            cfgdb.svc_instance_delete(id)
            LOG.debug("delete_nat_instance(): " + pformat(id))
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_nat_instances(self, context, filters=None, fields=None,
                          sorts=None, limit=None, marker=None,
                          page_reverse=False):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            svc_instances_info = cfgdb.svc_instance_list(context, filters)

            svc_instances_dicts = []
            for si_info in svc_instances_info:
                # verify transformation is conforming to api
                si_dict = self._make_svc_instance_dict(si_info['q_api_data'],
                                                       fields)

                si_dict.update(si_info['q_extra_data'])
                svc_instances_dicts.append(si_dict)

            LOG.debug(
                "get_nat_instances(): filter: " + pformat(filters)
                + 'data: ' + pformat(svc_instances_dicts))
            return svc_instances_dicts
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_nat_instance(self, context, id, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            si_info = cfgdb.svc_instance_read(id)

            # verify transformation is conforming to api
            si_dict = self._make_svc_instance_dict(si_info['q_api_data'],
                                                   fields)

            si_dict.update(si_info['q_extra_data'])

            LOG.debug("get_nat_instance(): " + pformat(si_dict))
            return self._fields(si_dict, fields)
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    # Security Group handlers
    def _make_security_group_rule_dict(self, security_group_rule, fields=None):
        res = {'id': security_group_rule['id'],
               'tenant_id': security_group_rule['tenant_id'],
               'security_group_id': security_group_rule['security_group_id'],
               'ethertype': security_group_rule['ethertype'],
               'direction': security_group_rule['direction'],
               'protocol': security_group_rule['protocol'],
               'port_range_min': security_group_rule['port_range_min'],
               'port_range_max': security_group_rule['port_range_max'],
               'remote_ip_prefix': security_group_rule['remote_ip_prefix'],
               'remote_group_id': security_group_rule['remote_group_id']}

        return self._fields(res, fields)

    def _make_security_group_dict(self, security_group, fields=None):
        res = {'id': security_group['id'],
               'name': security_group['name'],
               'tenant_id': security_group['tenant_id'],
               'description': security_group['description']}
        res['security_group_rules'] = [self._make_security_group_rule_dict(r)
                                       for r in security_group['rules']]
        return self._fields(res, fields)

    def create_security_group(self, context, security_group):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            sg_info = cfgdb.security_group_create(
                security_group['security_group'])

            # verify transformation is conforming to api
            sg_dict = self._make_security_group_dict(sg_info['q_api_data'])

            sg_dict.update(sg_info['q_extra_data'])

            LOG.debug("create_security_group(): " + pformat(sg_dict))
            return sg_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def delete_security_group(self, context, id):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            cfgdb.security_group_delete(id)
            LOG.debug("delete_security_group(): " + pformat(id))
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_security_groups(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            security_groups_info = cfgdb.security_group_list(context, filters)

            security_groups_dicts = []
            for sg_info in security_groups_info:
                # verify transformation is conforming to api
                sg_dict = self._make_security_group_dict(sg_info['q_api_data'],
                                                         fields)

                sg_dict.update(sg_info['q_extra_data'])
                security_groups_dicts.append(sg_dict)

            LOG.debug(
                "get_security_groups(): filter: " + pformat(filters)
                + 'data: ' + pformat(security_groups_dicts))
            return security_groups_dicts
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_security_group(self, context, id, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            sg_info = cfgdb.security_group_read(id)

            # verify transformation is conforming to api
            sg_dict = self._make_security_group_dict(sg_info['q_api_data'],
                                                     fields)

            sg_dict.update(sg_info['q_extra_data'])

            LOG.debug("get_security_group(): " + pformat(sg_dict))
            return self._fields(sg_dict, fields)
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def create_security_group_rule(self, context, security_group_rule):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            sgr_info = cfgdb.security_group_rule_create(
                security_group_rule['security_group_rule'])

            # verify transformation is conforming to api
            sgr_dict = self._make_security_group_rule_dict(
                sgr_info['q_api_data'])
            sgr_dict.update(sgr_info['q_extra_data'])

            LOG.debug("create_security_group_rule(): " + pformat(sgr_dict))
            return sgr_dict
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def delete_security_group_rule(self, context, id):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            cfgdb.security_group_rule_delete(id)
            LOG.debug("delete_security_group_rule(): " + pformat(id))
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_security_group_rules(self, context, filters=None, fields=None,
                                 sorts=None, limit=None, marker=None,
                                 page_reverse=False):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            security_group_rules_info = cfgdb.security_group_rule_list(filters)

            security_group_rules_dicts = []
            for sgr_info in security_group_rules_info:
                for sgr in sgr_info:
                    # verify transformation is conforming to api
                    sgr_dict = self._make_security_group_rule_dict(
                        sgr['q_api_data'], fields)
                    sgr_dict.update(sgr['q_extra_data'])
                    security_group_rules_dicts.append(sgr_dict)

            LOG.debug(
                "get_security_group_rules(): filter: " + pformat(filters) +
                'data: ' + pformat(security_group_rules_dicts))
            return security_group_rules_dicts
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

    def get_security_group_rule(self, context, id, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            sgr_info = cfgdb.security_group_rule_read(id)

            # verify transformation is conforming to api
            sgr_dict = {}
            if sgr_info != {}:
                sgr_dict = self._make_security_group_rule_dict(
                    sgr_info['q_api_data'], fields)
                sgr_dict.update(sgr_info['q_extra_data'])

            LOG.debug("get_security_group_rule(): " + pformat(sgr_dict))
            return self._fields(sgr_dict, fields)
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

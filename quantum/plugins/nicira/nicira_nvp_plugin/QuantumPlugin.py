# Copyright 2012 Nicira Networks, Inc.
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
# @author: Somik Behera, Nicira Networks, Inc.
# @author: Brad Hall, Nicira Networks, Inc.

import ConfigParser
import logging
import os
import sys

import NvpApiClient
import nvplib

from quantum.common import exceptions as exception
from quantum.plugins.nicira.nicira_nvp_plugin.api_client.client_eventlet \
     import (
    DEFAULT_CONCURRENT_CONNECTIONS,
    DEFAULT_FAILOVER_TIME,
    )
from quantum.plugins.nicira.nicira_nvp_plugin.api_client.request_eventlet \
     import (
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_RETRIES,
    DEFAULT_REDIRECTS,
    )


LOG = logging.getLogger("QuantumPlugin")


CONFIG_FILE = "nvp.ini"
CONFIG_FILE_PATHS = []
if os.environ.get('QUANTUM_HOME', None):
    CONFIG_FILE_PATHS.append('%s/etc' % os.environ['QUANTUM_HOME'])
CONFIG_FILE_PATHS.append("/etc/quantum/plugins/nicira")
CONFIG_KEYS = ["DEFAULT_TZ_UUID", "NVP_CONTROLLER_IP", "PORT", "USER",
               "PASSWORD"]


def initConfig(cfile=None):
    config = ConfigParser.ConfigParser()
    if cfile == None:
        if os.path.exists(CONFIG_FILE):
            cfile = CONFIG_FILE
        else:
            cfile = find_config(os.path.abspath(os.path.dirname(__file__)))

    if cfile == None:
        raise Exception("Configuration file \"%s\" doesn't exist" % (cfile))
    LOG.info("Using configuration file: %s" % cfile)
    config.read(cfile)
    LOG.debug("Config: %s" % config)
    return config


def find_config(basepath):
    LOG.info("Looking for %s in %s" % (CONFIG_FILE, basepath))
    for root, dirs, files in os.walk(basepath, followlinks=True):
        if CONFIG_FILE in files:
            return os.path.join(root, CONFIG_FILE)
    for alternate_path in CONFIG_FILE_PATHS:
        p = os.path.join(alternate_path, CONFIG_FILE)
        if os.path.exists(p):
            return p
    return None


def parse_config(config):
    """Backwards compatible parsing.

    :param config: ConfigParser object initilized with nvp.ini.
    :returns: A tuple consisting of a control cluster object and a
        plugin_config variable.
    raises: In general, system exceptions are not caught but are propagated
        up to the user. Config parsing is still very lightweight.
        At some point, error handling needs to be significantly
        enhanced to provide user friendly error messages, clean program
        exists, rather than exceptions propagated to the user.
    """
    # Extract plugin config parameters.
    try:
        failover_time = config.get('NVP', 'failover_time')
    except ConfigParser.NoOptionError, e:
        failover_time = str(DEFAULT_FAILOVER_TIME)

    try:
        concurrent_connections = config.get('NVP', 'concurrent_connections')
    except ConfigParser.NoOptionError, e:
        concurrent_connections = str(DEFAULT_CONCURRENT_CONNECTIONS)

    plugin_config = {
        'failover_time': failover_time,
        'concurrent_connections': concurrent_connections,
        }
    LOG.info('parse_config(): plugin_config == "%s"' % plugin_config)

    cluster = NVPCluster('cluster1')

    # Extract connection information.
    try:
        defined_connections = config.get('NVP', 'NVP_CONTROLLER_CONNECTIONS')

        for conn_key in defined_connections.split():
            args = [config.get('NVP', 'DEFAULT_TZ_UUID')]
            args.extend(config.get('NVP', conn_key).split(':'))
            try:
                cluster.add_controller(*args)
            except Exception, e:
                LOG.fatal('Invalid connection parameters: %s' % str(e))
                sys.exit(1)

        return cluster, plugin_config
    except Exception, e:
        LOG.info('No new style connections defined: %s' % e)

        # Old style controller specification.
        args = [config.get('NVP', k) for k in CONFIG_KEYS]
        try:
            cluster.add_controller(*args)
        except Exception, e:
            LOG.fatal('Invalid connection parameters.')
            sys.exit(1)

    return cluster, plugin_config


class NVPCluster(object):
    """Encapsulates controller connection and api_client.

    Initialized within parse_config().
    Accessed within the NvpPlugin class.

    Each element in the self.controllers list is a dictionary that
    contains the following keys:
        ip, port, user, password, default_tz_uuid

    There may be some redundancy here, but that has been done to provide
    future flexibility.
    """
    def __init__(self, name):
        self._name = name
        self.controllers = []
        self.api_client = None

    def __repr__(self):
        ss = ['{ "NVPCluster": [']
        ss.append('{ "name" : "%s" }' % self.name)
        ss.append(',')
        for c in self.controllers:
            ss.append(str(c))
            ss.append(',')
        ss.append('] }')
        return ''.join(ss)

    def add_controller(self, default_tz_uuid, ip, port, user, password,
                       request_timeout=DEFAULT_REQUEST_TIMEOUT,
                       http_timeout=DEFAULT_HTTP_TIMEOUT,
                       retries=DEFAULT_RETRIES, redirects=DEFAULT_REDIRECTS):
        """Add a new set of controller parameters.

        :param ip: IP address of controller.
        :param port: port controller is listening on.
        :param user: user name.
        :param password: user password.
        :param request_timeout: timeout for an entire API request.
        :param http_timeout: timeout for a connect to a controller.
        :param retries: maximum number of request retries.
        :param redirects: maximum number of server redirect responses to
            follow.
        :param default_tz_uuid: default transport zone uuid.
        """

        keys = ['ip', 'port', 'user', 'password', 'default_tz_uuid']
        controller_dict = dict([(k, locals()[k]) for k in keys])

        int_keys = ['request_timeout', 'http_timeout', 'retries', 'redirects']
        for k in int_keys:
            controller_dict[k] = int(locals()[k])

        self.controllers.append(controller_dict)

    def get_controller(self, idx):
        return self.controllers[idx]

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, val=None):
        self._name = val

    @property
    def host(self):
        return self.controllers[0]['ip']

    @property
    def port(self):
        return self.controllers[0]['port']

    @property
    def user(self):
        return self.controllers[0]['user']

    @property
    def password(self):
        return self.controllers[0]['password']

    @property
    def request_timeout(self):
        return self.controllers[0]['request_timeout']

    @property
    def http_timeout(self):
        return self.controllers[0]['http_timeout']

    @property
    def retries(self):
        return self.controllers[0]['retries']

    @property
    def redirects(self):
        return self.controllers[0]['redirects']

    @property
    def default_tz_uuid(self):
        return self.controllers[0]['default_tz_uuid']


class NvpPlugin(object):
    """
    NvpPlugin is a Quantum plugin that provides L2 Virtual Network
    functionality using NVP.
    """
    supported_extension_aliases = ["portstats"]

    def __init__(self, configfile=None, loglevel=None, cli=False):
        if loglevel:
            logging.basicConfig(level=loglevel)
            nvplib.LOG.setLevel(loglevel)
            NvpApiClient.LOG.setLevel(loglevel)

        config = initConfig(configfile)
        self.controller, self.plugin_config = parse_config(config)
        c = self.controller
        api_providers = [(x['ip'], x['port'], True) for x in c.controllers]

        c.api_client = NvpApiClient.NVPApiHelper(
            api_providers, c.user, c.password,
            request_timeout=c.request_timeout, http_timeout=c.http_timeout,
            retries=c.retries, redirects=c.redirects,
            failover_time=int(self.plugin_config['failover_time']),
            concurrent_connections=int(
                self.plugin_config['concurrent_connections']))

        c.api_client.login()

        # For testing..
        self.api_client = self.controller.api_client

    def get_all_networks(self, tenant_id, **kwargs):
        """
        Returns a dictionary containing all <network_uuid, network_name> for
        the specified tenant.

        :returns: a list of mapping sequences with the following signature:
                     [{'net-id': uuid that uniquely identifies
                                      the particular quantum network,
                        'net-name': a human-readable name associated
                                      with network referenced by net-id
                      },
                       ....
                       {'net-id': uuid that uniquely identifies the
                                       particular quantum network,
                        'net-name': a human-readable name associated
                                       with network referenced by net-id
                      }
                   ]
        :raises: None
        """
        networks = nvplib.get_all_networks(self.controller, tenant_id, [])
        LOG.debug("get_all_networks() completed for tenant %s: %s" %
                  (tenant_id, networks))
        return networks

    def create_network(self, tenant_id, net_name, **kwargs):
        """
        Creates a new Virtual Network, and assigns it a symbolic name.
        :returns: a sequence of mappings with the following signature:
                    {'net-id': uuid that uniquely identifies the
                                     particular quantum network,
                     'net-name': a human-readable name associated
                                    with network referenced by net-id
                   }
        :raises:
        """
        kwargs["controller"] = self.controller
        return nvplib.create_network(tenant_id, net_name, **kwargs)

    def create_custom_network(self, tenant_id, net_name, transport_zone,
                              controller):
        return self.create_network(tenant_id, net_name,
                                   network_type="custom",
                                   transport_zone=transport_zone,
                                   controller=controller)

    def delete_network(self, tenant_id, netw_id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.

        :returns: a sequence of mappings with the following signature:
                    {'net-id': uuid that uniquely identifies the
                                 particular quantum network
                   }
        :raises: exception.NetworkInUse
        :raises: exception.NetworkNotFound
        """
        if not nvplib.check_tenant(self.controller, netw_id, tenant_id):
            raise exception.NetworkNotFound(net_id=netw_id)
        nvplib.delete_network(self.controller, netw_id)

        LOG.debug("delete_network() completed for tenant: %s" % tenant_id)
        return {'net-id': netw_id}

    def get_network_details(self, tenant_id, netw_id):
        """
        Retrieves a list of all the remote vifs that
        are attached to the network.

        :returns: a sequence of mappings with the following signature:
                    {'net-id': uuid that uniquely identifies the
                                particular quantum network
                     'net-name': a human-readable name associated
                                 with network referenced by net-id
                     'net-ifaces': ['vif1_on_network_uuid',
                                    'vif2_on_network_uuid',...,'vifn_uuid']
                   }
        :raises: exception.NetworkNotFound
        :raises: exception.QuantumException
        """
        if not nvplib.check_tenant(self.controller, netw_id, tenant_id):
            raise exception.NetworkNotFound(net_id=netw_id)
        result = None
        remote_vifs = []
        switch = netw_id
        lports = nvplib.query_ports(self.controller, switch,
                                    relations="LogicalPortAttachment")

        for port in lports:
            relation = port["_relations"]
            vic = relation["LogicalPortAttachment"]
            if "vif_uuid" in vic:
                remote_vifs.append(vic["vif_uuid"])

        if not result:
            result = nvplib.get_network(self.controller, switch)

        d = {
            "net-id": netw_id,
            "net-ifaces": remote_vifs,
            "net-name": result["display_name"],
            "net-op-status": "UP",
            }
        LOG.debug("get_network_details() completed for tenant %s: %s" %
                  (tenant_id, d))
        return d

    def update_network(self, tenant_id, netw_id, **kwargs):
        """
        Updates the properties of a particular Virtual Network.

        :returns: a sequence of mappings representing the new network
                    attributes, with the following signature:
                    {'net-id': uuid that uniquely identifies the
                                 particular quantum network
                     'net-name': the new human-readable name
                                  associated with network referenced by net-id
                   }
        :raises: exception.NetworkNotFound
        """
        if not nvplib.check_tenant(self.controller, netw_id, tenant_id):
            raise exception.NetworkNotFound(net_id=netw_id)
        result = nvplib.update_network(self.controller, netw_id, **kwargs)
        LOG.debug("update_network() completed for tenant: %s" % tenant_id)
        return {
            'net-id': netw_id,
            'net-name': result["display_name"],
            'net-op-status': "UP",
            }

    def get_all_ports(self, tenant_id, netw_id, **kwargs):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.

        :returns: a list of mapping sequences with the following signature:
                     [{'port-id': uuid representing a particular port
                                    on the specified quantum network
                      },
                       ....
                       {'port-id': uuid representing a particular port
                                     on the specified quantum network
                      }
                     ]
        :raises: exception.NetworkNotFound
        """
        ids = []
        filters = kwargs.get("filter_opts") or {}
        if not nvplib.check_tenant(self.controller, netw_id, tenant_id):
            raise exception.NetworkNotFound(net_id=netw_id)
        LOG.debug("Getting logical ports on lswitch: %s" % netw_id)
        lports = nvplib.query_ports(self.controller, netw_id, fields="uuid",
                                    filters=filters)
        for port in lports:
            ids.append({"port-id": port["uuid"]})

        # Delete from the filter so that Quantum doesn't attempt to filter on
        # this too
        if filters and "attachment" in filters:
            del filters["attachment"]

        LOG.debug("get_all_ports() completed for tenant: %s" % tenant_id)
        LOG.debug("returning port listing:")
        LOG.debug(ids)
        return ids

    def create_port(self, tenant_id, netw_id, port_init_state=None, **params):
        """
        Creates a port on the specified Virtual Network.

        :returns: a mapping sequence with the following signature:
                    {'port-id': uuid representing the created port
                                   on specified quantum network
                   }
        :raises: exception.NetworkNotFound
        :raises: exception.StateInvalid
        """
        if not nvplib.check_tenant(self.controller, netw_id, tenant_id):
            raise exception.NetworkNotFound(net_id=netw_id)
        params["controller"] = self.controller
        if not nvplib.check_tenant(self.controller, netw_id, tenant_id):
            raise exception.NetworkNotFound(net_id=netw_id)
        result = nvplib.create_port(tenant_id, netw_id, port_init_state,
          **params)
        d = {
            "port-id": result["uuid"],
            "port-op-status": result["port-op-status"],
            }
        LOG.debug("create_port() completed for tenant %s: %s" % (tenant_id, d))
        return d

    def update_port(self, tenant_id, netw_id, portw_id, **params):
        """
        Updates the properties of a specific port on the
        specified Virtual Network.

        :returns: a mapping sequence with the following signature:
                    {'port-id': uuid representing the
                                 updated port on specified quantum network
                     'port-state': update port state (UP or DOWN)
                   }
        :raises: exception.StateInvalid
        :raises: exception.PortNotFound
        """
        if not nvplib.check_tenant(self.controller, netw_id, tenant_id):
            raise exception.NetworkNotFound(net_id=netw_id)
        LOG.debug("Update port request: %s" % (params))
        params["controller"] = self.controller
        result = nvplib.update_port(netw_id, portw_id, **params)
        LOG.debug("update_port() completed for tenant: %s" % tenant_id)
        port = {
            'port-id': portw_id,
            'port-state': result["admin_status_enabled"],
            'port-op-status': result["port-op-status"],
            }
        LOG.debug("returning updated port %s: " % port)
        return port

    def delete_port(self, tenant_id, netw_id, portw_id):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface is first un-plugged and then the port
        is deleted.

        :returns: a mapping sequence with the following signature:
                    {'port-id': uuid representing the deleted port
                                 on specified quantum network
                   }
        :raises: exception.PortInUse
        :raises: exception.PortNotFound
        :raises: exception.NetworkNotFound
        """
        if not nvplib.check_tenant(self.controller, netw_id, tenant_id):
            raise exception.NetworkNotFound(net_id=netw_id)
        nvplib.delete_port(self.controller, netw_id, portw_id)
        LOG.debug("delete_port() completed for tenant: %s" % tenant_id)
        return {"port-id": portw_id}

    def get_port_details(self, tenant_id, netw_id, portw_id):
        """
        This method allows the user to retrieve a remote interface
        that is attached to this particular port.

        :returns: a mapping sequence with the following signature:
                    {'port-id': uuid representing the port on
                                 specified quantum network
                     'net-id': uuid representing the particular
                                quantum network
                     'attachment': uuid of the virtual interface
                                   bound to the port, None otherwise
                    }
        :raises: exception.PortNotFound
        :raises: exception.NetworkNotFound
        """
        if not nvplib.check_tenant(self.controller, netw_id, tenant_id):
            raise exception.NetworkNotFound(net_id=netw_id)
        port = nvplib.get_port(self.controller, netw_id, portw_id,
          "LogicalPortAttachment")
        state = "ACTIVE" if port["admin_status_enabled"] else "DOWN"
        op_status = nvplib.get_port_status(self.controller, netw_id, portw_id)

        relation = port["_relations"]
        attach_type = relation["LogicalPortAttachment"]["type"]

        vif_uuid = "None"
        if attach_type == "VifAttachment":
            vif_uuid = relation["LogicalPortAttachment"]["vif_uuid"]

        d = {
            "port-id": portw_id, "attachment": vif_uuid,
            "net-id": netw_id, "port-state": state,
            "port-op-status": op_status,
            }
        LOG.debug("Port details for tenant %s: %s" % (tenant_id, d))
        return d

    def plug_interface(self, tenant_id, netw_id, portw_id,
                       remote_interface_id):
        """
        Attaches a remote interface to the specified port on the
        specified Virtual Network.

        :returns: None
        :raises: exception.NetworkNotFound
        :raises: exception.PortNotFound
        :raises: exception.AlreadyAttached
                    (? should the network automatically unplug/replug)
        """
        if not nvplib.check_tenant(self.controller, netw_id, tenant_id):
            raise exception.NetworkNotFound(net_id=netw_id)
        result = nvplib.plug_interface(self.controller, netw_id, portw_id,
          "VifAttachment", attachment=remote_interface_id)
        LOG.debug("plug_interface() completed for %s: %s" %
                  (tenant_id, result))

    def unplug_interface(self, tenant_id, netw_id, portw_id):
        """
        Detaches a remote interface from the specified port on the
        specified Virtual Network.

        :returns: None
        :raises: exception.NetworkNotFound
        :raises: exception.PortNotFound
        """
        if not nvplib.check_tenant(self.controller, netw_id, tenant_id):
            raise exception.NetworkNotFound(net_id=netw_id)
        result = nvplib.unplug_interface(self.controller, netw_id, portw_id)

        LOG.debug("unplug_interface() completed for tenant %s: %s" %
                  (tenant_id, result))

    def get_port_stats(self, tenant_id, network_id, port_id):
        """
        Returns port statistics for a given port.

        {
          "rx_packets": 0,
          "rx_bytes": 0,
          "tx_errors": 0,
          "rx_errors": 0,
          "tx_bytes": 0,
          "tx_packets": 0
        }

        :returns: dict() of stats
        :raises: exception.NetworkNotFound
        :raises: exception.PortNotFound
        """
        if not nvplib.check_tenant(self.controller, network_id, tenant_id):
            raise exception.NetworkNotFound(net_id=network_id)
        return nvplib.get_port_stats(self.controller, network_id, port_id)

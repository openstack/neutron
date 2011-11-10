#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Nicira Networks, Inc.
# Copyright 2011 Citrix Systems
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
# @author: Somik Behera, Nicira Networks, Inc.
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Salvatore Orlando, Citrix

""" Functions providing implementation for CLI commands. """

import logging
import os
import sys

FORMAT = "json"
LOG = logging.getLogger('quantum.client.cli_lib')


class OutputTemplate(object):
    """ A class for generating simple templated output.
        Based on Python templating mechanism.
        Templates can also express attributes on objects, such as network.id;
        templates can also be nested, thus allowing for iteration on inner
        templates.

        Examples:
        1) template with class attributes
        Name: %(person.name)s \n
        Surname: %(person.surname)s \n
        2) template with iteration
        Telephone numbers: \n
        %(phone_numbers|Telephone number:%(number)s)
        3) template with iteration and class attributes
        Addresses: \n
        %(Addresses|Street:%(address.street)s\nNumber%(address.number))

        Instances of this class are initialized with a template string and
        the dictionary for performing substition. The class implements the
        __str__ method, so it can be directly printed.
    """

    def __init__(self, template, data):
        self._template = template
        self.data = data

    def __str__(self):
        return self._template % self

    def __getitem__(self, key):
        items = key.split("|")
        if len(items) == 1:
            return self._make_attribute(key)
        else:
            # Note(salvatore-orlando): items[0] must be subscriptable
            return self._make_list(self.data[items[0]], items[1])

    def _make_attribute(self, item):
        """ Renders an entity attribute key in the template.
           e.g.: entity.attribute
        """
        items = item.split('.')
        if len(items) == 1:
            return self.data[item]
        elif len(items) == 2:
            return self.data[items[0]][items[1]]

    def _make_list(self, items, inner_template):
        """ Renders a list key in the template.
            e.g.: %(list|item data:%(item))
        """
        #make sure list is subscriptable
        if not hasattr(items, '__getitem__'):
            raise Exception("Element is not iterable")
        return "\n".join([inner_template % item for item in items])


class CmdOutputTemplate(OutputTemplate):
    """ This class provides templated output for CLI commands.
        Extends OutputTemplate loading a different template for each command.
    """

    _templates = {
        "list_nets":      "Virtual Networks for Tenant %(tenant_id)s\n" +
                          "%(networks|\tNetwork ID: %(id)s)s",
        "show_net":       "Network ID: %(network.id)s\n" +
                          "network Name: %(network.name)s",
        "create_net":     "Created a new Virtual Network with ID: " +
                          "%(network_id)s\n" +
                          "for Tenant: %(tenant_id)s",
        "update_net":     "Updated Virtual Network with ID: %(network.id)s\n" +
                          "for Tenant: %(tenant_id)s\n",
        "delete_net":     "Deleted Virtual Network with ID: %(network_id)s\n" +
                          "for Tenant %(tenant_id)s",
        "list_ports":     "Ports on Virtual Network: %(network_id)s\n" +
                          "for Tenant: %(tenant_id)s\n" +
                          "%(ports|\tLogical Port: %(id)s)s",
        "create_port":    "Created new Logical Port with ID: %(port_id)s\n" +
                          "on Virtual Network: %(network_id)s\n" +
                          "for Tenant: %(tenant_id)s",
        "show_port":      "Logical Port ID: %(port.id)s\n" +
                          "administrative State: %(port.state)s\n" +
                          "interface: %(port.attachment)s\n" +
                          "on Virtual Network: %(network_id)s\n" +
                          "for Tenant: %(tenant_id)s",
        "update_port":    "Updated Logical Port " +
                          "with ID: %(port.id)s\n" +
                          "on Virtual Network: %(network_id)s\n" +
                          "for tenant: %(tenant_id)s",
        "delete_port":    "Deleted Logical Port with ID: %(port_id)s\n" +
                          "on Virtual Network: %(network_id)s\n" +
                          "for Tenant: %(tenant_id)s",
        "plug_iface":     "Plugged interface %(attachment)s\n" +
                          "into Logical Port: %(port_id)s\n" +
                          "on Virtual Network: %(network_id)s\n" +
                          "for Tenant: %(tenant_id)s",
        "unplug_iface":   "Unplugged interface from Logical Port:" +
                          "%(port_id)s\n" +
                          "on Virtual Network: %(network_id)s\n" +
                          "for Tenant: %(tenant_id)s"}

    def __init__(self, cmd, data):
        super(CmdOutputTemplate, self).__init__(self._templates[cmd], data)


def _handle_exception(ex):
    LOG.exception(sys.exc_info())
    print "Exception:%s - %s" % (sys.exc_info()[0], sys.exc_info()[1])
    status_code = None
    message = None
    # Retrieve dict at 1st element of tuple at last argument
    if ex.args and isinstance(ex.args[-1][0], dict):
        status_code = ex.args[-1][0].get('status_code', None)
        message = ex.args[-1][0].get('message', None)
        msg_1 = "Command failed with error code: %s" \
                % (status_code or '<missing>')
        msg_2 = "Error message:%s" % (message or '<missing>')
        LOG.exception(msg_1 + "-" + msg_2)
        print msg_1
        print msg_2


def prepare_output(cmd, tenant_id, response):
    LOG.debug("Preparing output for response:%s", response)
    response['tenant_id'] = tenant_id
    output = str(CmdOutputTemplate(cmd, response))
    LOG.debug("Finished preparing output for command:%s", cmd)
    return output


def list_nets(client, *args):
    tenant_id = args[0]
    res = client.list_networks()
    LOG.debug("Operation 'list_networks' executed.")
    output = prepare_output("list_nets", tenant_id, res)
    print output


def create_net(client, *args):
    tenant_id, name = args
    data = {'network': {'name': name}}
    new_net_id = None
    try:
        res = client.create_network(data)
        new_net_id = res["network"]["id"]
        LOG.debug("Operation 'create_network' executed.")
        output = prepare_output("create_net", tenant_id,
                                          dict(network_id=new_net_id))
        print output
    except Exception as ex:
        _handle_exception(ex)


def delete_net(client, *args):
    tenant_id, network_id = args
    try:
        client.delete_network(network_id)
        LOG.debug("Operation 'delete_network' executed.")
        output = prepare_output("delete_net", tenant_id,
                            dict(network_id=network_id))
        print output
    except Exception as ex:
        _handle_exception(ex)


def show_net(client, *args):
    tenant_id, network_id = args
    try:
        #NOTE(salvatore-orlando) changed for returning exclusively
        # output for GET /networks/{net-id} API operation
        res = client.show_network_details(network_id)["network"]
        LOG.debug("Operation 'show_network_details' executed.")
        output = prepare_output("show_net", tenant_id,
                                          dict(network=res))
        print output
    except Exception as ex:
        _handle_exception(ex)


def update_net(client, *args):
    tenant_id, network_id, param_data = args
    data = {'network': {}}
    for kv in param_data.split(","):
        k, v = kv.split("=")
        data['network'][k] = v
    data['network']['id'] = network_id
    try:
        client.update_network(network_id, data)
        LOG.debug("Operation 'update_network' executed.")
        # Response has no body. Use data for populating output
        output = prepare_output("update_net", tenant_id, data)
        print output
    except Exception as ex:
        _handle_exception(ex)


def list_ports(client, *args):
    tenant_id, network_id = args
    try:
        ports = client.list_ports(network_id)
        LOG.debug("Operation 'list_ports' executed.")
        data = ports
        data['network_id'] = network_id
        output = prepare_output("list_ports", tenant_id, data)
        print output
    except Exception as ex:
        _handle_exception(ex)


def create_port(client, *args):
    tenant_id, network_id = args
    try:
        res = client.create_port(network_id)
        LOG.debug("Operation 'create_port' executed.")
        new_port_id = res["port"]["id"]
        output = prepare_output("create_port", tenant_id,
                                dict(network_id=network_id,
                                     port_id=new_port_id))
        print output
    except Exception as ex:
        _handle_exception(ex)


def delete_port(client, *args):
    tenant_id, network_id, port_id = args
    try:
        client.delete_port(network_id, port_id)
        LOG.debug("Operation 'delete_port' executed.")
        output = prepare_output("delete_port", tenant_id,
                                dict(network_id=network_id,
                                     port_id=port_id))
        print output
    except Exception as ex:
        _handle_exception(ex)
        return


def show_port(client, *args):
    tenant_id, network_id, port_id = args
    try:
        port = client.show_port_details(network_id, port_id)["port"]
        LOG.debug("Operation 'list_port_details' executed.")
        #NOTE(salvatore-orland): current API implementation does not
        #return attachment with GET operation on port. Once API alignment
        #branch is merged, update client to use the detail action.
        # (danwent) Until then, just make additonal webservice call.
        attach = client.show_port_attachment(network_id, port_id)['attachment']
        if "id" in attach:
            port['attachment'] = attach['id']
        else:
            port['attachment'] = '<none>'
        output = prepare_output("show_port", tenant_id,
                                dict(network_id=network_id,
                                     port=port))
        print output
    except Exception as ex:
        _handle_exception(ex)


def update_port(client, *args):
    tenant_id, network_id, port_id, param_data = args
    data = {'port': {}}
    for kv in param_data.split(","):
        k, v = kv.split("=")
        data['port'][k] = v
    data['network_id'] = network_id
    data['port']['id'] = port_id
    try:
        client.update_port(network_id, port_id, data)
        LOG.debug("Operation 'udpate_port' executed.")
        # Response has no body. Use data for populating output
        output = prepare_output("update_port", tenant_id, data)
        print output
    except Exception as ex:
        _handle_exception(ex)


def plug_iface(client, *args):
    tenant_id, network_id, port_id, attachment = args
    try:
        data = {'attachment': {'id': '%s' % attachment}}
        client.attach_resource(network_id, port_id, data)
        LOG.debug("Operation 'attach_resource' executed.")
        output = prepare_output("plug_iface", tenant_id,
                                dict(network_id=network_id,
                                     port_id=port_id,
                                     attachment=attachment))
        print output
    except Exception as ex:
        _handle_exception(ex)


def unplug_iface(client, *args):
    tenant_id, network_id, port_id = args
    try:
        client.detach_resource(network_id, port_id)
        LOG.debug("Operation 'detach_resource' executed.")
        output = prepare_output("unplug_iface", tenant_id,
                                dict(network_id=network_id,
                                     port_id=port_id))
        print output
    except Exception as ex:
        _handle_exception(ex)

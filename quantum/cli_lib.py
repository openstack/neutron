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

import Cheetah.Template as cheetah_template
import logging
import os
import sys

FORMAT = "json"
CLI_TEMPLATE = "cli_output.template"
LOG = logging.getLogger('quantum.cli_lib')


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
    """ Fills a cheetah template with the response """
    #add command and tenant to response for output generation
    LOG.debug("Preparing output for response:%s", response)
    response['cmd'] = cmd
    response['tenant_id'] = tenant_id
    template_path = os.path.join(os.path.dirname(__file__), CLI_TEMPLATE)
    template_file = open(template_path).read()
    output = str(cheetah_template.Template(template_file,
                                           searchList=response))
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
        output = prepare_output("show_net", tenant_id, dict(network=res))
        print output
    except Exception as ex:
        _handle_exception(ex)


def rename_net(client, *args):
    tenant_id, network_id, name = args
    data = {'network': {'name': '%s' % name}}
    try:
        client.update_network(network_id, data)
        LOG.debug("Operation 'update_network' executed.")
        # Response has no body. Use data for populating output
        data['network']['id'] = network_id
        output = prepare_output("rename_net", tenant_id, data)
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


def set_port_state(client, *args):
    tenant_id, network_id, port_id, new_state = args
    data = {'port': {'state': '%s' % new_state}}
    try:
        client.set_port_state(network_id, port_id, data)
        LOG.debug("Operation 'set_port_state' executed.")
        # Response has no body. Use data for populating output
        data['network_id'] = network_id
        data['port']['id'] = port_id
        output = prepare_output("set_port_state", tenant_id, data)
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

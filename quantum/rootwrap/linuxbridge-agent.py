# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 Openstack, LLC.
# All Rights Reserved.
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


from quantum.rootwrap import filters

filterlist = [
    # quantum/plugins/linuxbridge/agent/linuxbridge_quantum_agent.py:
    #   'brctl', 'addbr', bridge_name
    #   'brctl', 'addif', bridge_name, interface
    #   'brctl', 'addif', bridge_name, tap_device_name
    #   'brctl', 'delbr', bridge_name
    #   'brctl', 'delif', bridge_name, interface_name
    #   'brctl', 'delif', current_bridge_name, ...
    #   'brctl', 'setfd', bridge_name, ...
    #   'brctl', 'stp', bridge_name, 'off'
    filters.CommandFilter("/usr/sbin/brctl", "root"),
    filters.CommandFilter("/sbin/brctl", "root"),

    # quantum/plugins/linuxbridge/agent/linuxbridge_quantum_agent.py:
    #   'ip', 'link', 'add', 'link', ...
    #   'ip', 'link', 'delete', interface
    #   'ip', 'link', 'set', bridge_name, 'down'
    #   'ip', 'link', 'set', bridge_name, 'up'
    #   'ip', 'link', 'set', interface, 'down'
    #   'ip', 'link', 'set', interface, 'up'
    #   'ip', 'link', 'show', 'dev', device
    #   'ip', 'tuntap'
    #   'ip', 'tuntap'
    filters.CommandFilter("/usr/sbin/ip", "root"),
    filters.CommandFilter("/sbin/ip", "root"),
    ]

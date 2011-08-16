"""
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
# @author: Rohit Agarwalla, Cisco Systems Inc.
#
"""

import subprocess


def get_next_dynic(argv=[]):
    """Get the next available dynamic nic on this host"""
    cmd = ["ifconfig", "-a"]
    f_cmd_output = subprocess.Popen(cmd, stdout=subprocess.PIPE).\
                   communicate()[0]
    eths = [lines.split(' ')[0] for lines in f_cmd_output.splitlines() \
            if "eth" in lines]
    #print eths
    for eth in eths:
        cmd = ["ethtool", "-i", eth]
        f_cmd_output = subprocess.Popen(cmd, stdout=subprocess.PIPE).\
                       communicate()[0]
        bdf = [lines.split(' ')[1] for lines in f_cmd_output.splitlines() \
               if "bus-info" in lines]
        #print bdf
        cmd = ["lspci", "-n", "-s", bdf[0]]
        f_cmd_output = subprocess.Popen(cmd, stdout=subprocess.PIPE).\
                       communicate()[0]
        deviceid = [(lines.split(':')[3]).split(' ')[0] \
                    for lines in f_cmd_output.splitlines()]
        #print deviceid
        if deviceid[0] == "0044":
            cmd = ["/sbin/ip", "link", "show", eth]
            f_cmd_output = subprocess.Popen(cmd, stdout=subprocess.PIPE).\
                           communicate()[0]
            used = [lines for lines in f_cmd_output.splitlines() \
                    if "UP" in lines]
            if not used:
                break
    return eth

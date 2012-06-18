# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Locaweb.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# @author: Juliano Martinez, Locaweb.

from quantum.rootwrap import filters

filterlist = [
    # quantum/agent/linux/iptables_manager.py
    #   "iptables-save", ...
    filters.CommandFilter("/sbin/iptables-save", "root"),
    filters.CommandFilter("/sbin/iptables-restore", "root"),
    filters.CommandFilter("/sbin/ip6tables-save", "root"),
    filters.CommandFilter("/sbin/ip6tables-restore", "root"),

    # quantum/agent/linux/iptables_manager.py
    #   "iptables", "-A", ...
    filters.CommandFilter("/sbin/iptables", "root"),
    filters.CommandFilter("/sbin/ip6tables", "root"),
]

# Copyright (C) 2014 VA Linux Systems Japan K.K.
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
#
# @author: YAMAMOTO Takashi, VA Linux Systems Japan K.K.


class Port(object):
    def __init__(self, port_name, ofport):
        self.port_name = port_name
        self.ofport = ofport

    @classmethod
    def from_ofp_port(cls, ofp_port):
        """Convert from ryu OFPPort."""
        return cls(port_name=ofp_port.name, ofport=ofp_port.port_no)

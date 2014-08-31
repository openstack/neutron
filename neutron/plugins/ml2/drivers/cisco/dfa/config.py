# Copyright 2014 Cisco Systems, Inc.
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


from oslo.config import cfg


ml2_cisco_dfa_opts = [
    cfg.StrOpt('dcnm_ip', default='0.0.0.0',
               help=_("IP address of DCNM.")),
    cfg.StrOpt('dcnm_user', default='user',
               help=_("User login name for DCNM.")),
    cfg.StrOpt('dcnm_password', default='password',
               secret=True,
               help=_("Login password for DCNM.")),
    cfg.StrOpt('gateway_mac', default='00:00:DE:AD:BE:EF',
               help=_("Gateway mac address when using proxy mode.")),
]

cfg.CONF.register_opts(ml2_cisco_dfa_opts, "ml2_cisco_dfa")


class CiscoDFAConfig(object):
    """Cisco DFA Mechanism Driver Configuration class."""

    dfa_cfg = {}

    def __init__(self):
        multi_parser = cfg.MultiConfigParser()
        read_ok = multi_parser.read(cfg.CONF.config_file)

        if len(read_ok) != len(cfg.CONF.config_file):
            raise cfg.Error(_("Failed to read config files %(file)s") %
                            {'file': cfg.CONF.config_file})

        for parsed_file in multi_parser.parsed:
            for parsed_item in parsed_file.keys():
                for key, value in parsed_file[parsed_item].items():
                    if parsed_item == 'mech_driver_agent':
                        self.dfa_cfg[key] = value

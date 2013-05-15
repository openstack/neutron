# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira, Inc.
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

from oslo.config import cfg

from quantum import scheduler

core_opts = [
    cfg.BoolOpt('metadata_dhcp_host_route', default=False),
]

nvp_opts = [
    cfg.IntOpt('max_lp_per_bridged_ls', default=64,
               help=_("Maximum number of ports of a logical switch on a "
                      "bridged transport zone (default 64)")),
    cfg.IntOpt('max_lp_per_overlay_ls', default=256,
               help=_("Maximum number of ports of a logical switch on an "
                      "overlay transport zone (default 64)")),
    cfg.IntOpt('concurrent_connections', default=5,
               help=_("Maximum concurrent connections")),
    cfg.IntOpt('nvp_gen_timeout', default=-1,
               help=_("Number of seconds a generation id should be valid for "
                      "(default -1 meaning do not time out)")),
    cfg.StrOpt('default_cluster_name',
               help=_("Default cluster name")),
    cfg.BoolOpt('enable_metadata_access_network', default=True,
                help=_("Enables dedicated connection to the metadata proxy "
                       "for metadata server access via Quantum router")),
    cfg.StrOpt('default_transport_type', default='stt',
               help=_("The default network tranport type to use (stt, gre, "
                      "bridge, ipsec_gre, or ipsec_stt)")),
]

cluster_opts = [
    cfg.StrOpt('default_tz_uuid',
               help=_("This is uuid of the default NVP Transport zone that "
                      "will be used for creating tunneled isolated "
                      "\"Quantum\" networks. It needs to be created in NVP "
                      "before starting Quantum with the nvp plugin.")),
    cfg.StrOpt('nvp_cluster_uuid',
               help=_("Optional paramter identifying the UUID of the cluster "
                      "in NVP.  This can be retrieved from NVP management "
                      "console \"admin\" section.")),
    cfg.StrOpt('nova_zone_id',
               help=_("Optional parameter identifying the Nova \"zone\" that "
                      "maps to this NVP cluster.")),
    cfg.MultiStrOpt('nvp_controller_connection',
                    help=_("Describes a connection to a single NVP "
                           "controller. A different connection for each "
                           "controller in the cluster can be specified; "
                           "there must be at least one connection per "
                           "cluster.")),
    cfg.StrOpt('default_l3_gw_service_uuid',
               help=_("Unique identifier of the NVP L3 Gateway service "
                      "which will be used for implementing routers and "
                      "floating IPs")),
    cfg.StrOpt('default_l2_gw_service_uuid',
               help=_("Unique identifier of the NVP L2 Gateway service "
                      "which will be used by default for network gateways")),
    cfg.StrOpt('default_interface_name', default='breth0',
               help=_("Name of the interface on a L2 Gateway transport node"
                      "which should be used by default when setting up a "
                      "network connection")),
]

# Register the configuration options
cfg.CONF.register_opts(core_opts)
cfg.CONF.register_opts(nvp_opts, "NVP")
cfg.CONF.register_opts(scheduler.AGENTS_SCHEDULER_OPTS)


class ClusterConfigOptions(cfg.ConfigOpts):

    def __init__(self, config_options):
        super(ClusterConfigOptions, self).__init__()
        self._group_mappings = {}
        self._config_opts = config_options._config_opts
        self._cparser = config_options._cparser
        self._oparser = config_options._oparser
        self.register_cli_opts(self._config_opts)

    def _do_get(self, name, group=None):
        """Look up an option value.

        :param name: the opt name (or 'dest', more precisely)
        :param group: an OptGroup
        :returns: the option value, or a GroupAttr object
        :raises: NoSuchOptError, NoSuchGroupError, ConfigFileValueError,
                 TemplateSubstitutionError
        """
        if group is None and name in self._groups:
            return self.GroupAttr(self, self._get_group(name))

        info = self._get_opt_info(name, group)
        opt = info['opt']

        if 'override' in info:
            return info['override']

        values = []
        if self._cparser is not None:
            section = group.name if group is not None else 'DEFAULT'
            # Check if the name of the group maps to something else in
            # the conf file.Otherwise leave the section name unchanged

            section = self._group_mappings.get(section, section)
            try:
                value = opt._get_from_config_parser(self._cparser, section)
            except KeyError:
                pass
            except ValueError as ve:
                raise cfg.ConfigFileValueError(str(ve))
            else:
                if not opt.multi:
                    # No need to continue since the last value wins
                    return value[-1]
                values.extend(value)

        name = name if group is None else group.name + '_' + name
        value = self._cli_values.get(name)
        if value is not None:
            if not opt.multi:
                return value

            return value + values

        if values:
            return values

        if 'default' in info:
            return info['default']

        return opt.default

    def register_opts(self, opts, group_internal_name=None, group=None):
        """Register multiple option schemas at once."""
        if group_internal_name:
            self._group_mappings[group] = group_internal_name
        for opt in opts:
            self.register_opt(opt, group, clear_cache=False)


def _retrieve_extra_groups(conf, key=None, delimiter=':'):
    """retrieve configuration groups not listed above."""
    results = []
    for parsed_file in cfg.CONF._cparser.parsed:
        for parsed_item in parsed_file.keys():
            if parsed_item not in cfg.CONF:
                items = key and parsed_item.split(delimiter)
                if not key or key == items[0]:
                    results.append(parsed_item)
    return results


def register_cluster_groups(conf):
    """retrieve configuration groups for nvp clusters."""
    cluster_names = []
    cluster_tags = _retrieve_extra_groups(conf, "CLUSTER")
    for tag in cluster_tags:
        cluster_name = tag.split(':')[1]
        conf.register_opts(cluster_opts, tag, cluster_name)
        cluster_names.append(cluster_name)
    return cluster_names

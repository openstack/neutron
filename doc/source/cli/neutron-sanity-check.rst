.. This file is manually generated, unlike many of the other chapters.

========================================
neutron-sanity-check command-line client
========================================

The :command:`neutron-sanity-check` client is a tool that checks various
sanity about the Networking service.

This chapter documents :command:`neutron-sanity-check` version ``10.0.0``.

neutron-sanity-check usage
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   usage: neutron-sanity-check [-h] [--arp_header_match] [--arp_responder]
                               [--bridge_firewalling] [--config-dir DIR]
                               [--config-file PATH] [--debug] [--dhcp_release6]
                               [--dibbler_version] [--dnsmasq_version]
                               [--ebtables_installed] [--icmpv6_header_match]
                               [--ip6tables_installed] [--ip_nonlocal_bind]
                               [--iproute2_vxlan] [--ipset_installed]
                               [--keepalived_ipv6_support]
                               [--log-config-append PATH]
                               [--log-date-format DATE_FORMAT]
                               [--log-dir LOG_DIR] [--log-file PATH]
                               [--noarp_header_match] [--noarp_responder]
                               [--nobridge_firewalling] [--nodebug]
                               [--nodhcp_release6] [--nodibbler_version]
                               [--nodnsmasq_version] [--noebtables_installed]
                               [--noicmpv6_header_match]
                               [--noip6tables_installed] [--noip_nonlocal_bind]
                               [--noiproute2_vxlan] [--noipset_installed]
                               [--nokeepalived_ipv6_support] [--nonova_notify]
                               [--noovs_conntrack] [--noovs_geneve]
                               [--noovs_patch] [--noovs_vxlan] [--noovsdb_native]
                               [--noread_netns] [--nouse-syslog] [--nova_notify]
                               [--noverbose] [--novf_extended_management]
                               [--novf_management] [--nowatch-log-file]
                               [--ovs_conntrack] [--ovs_geneve] [--ovs_patch]
                               [--ovs_vxlan] [--ovsdb_native] [--read_netns]
                               [--state_path STATE_PATH]
                               [--syslog-log-facility SYSLOG_LOG_FACILITY]
                               [--use-syslog] [--verbose] [--version]
                               [--vf_extended_management] [--vf_management]
                               [--watch-log-file]

neutron-sanity-check optional arguments
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``-h, --help``
  show this help message and exit

``--arp_header_match``
  Check for ARP header match support

``--arp_responder``
  Check for ARP responder support

``--bridge_firewalling``
  Check bridge firewalling

``--ip_nonlocal_bind``
  Check ip_nonlocal_bind kernel option works with network namespaces.

``--config-dir DIR``
  Path to a config directory to pull ``*.conf`` files from.
  This file set is sorted, so as to provide a predictable parse order
  if individual options are over-ridden. The set is parsed after the file(s)
  specified via previous --config-file, arguments hence
  over-ridden options in the directory take precedence.

``--config-file PATH``
  Path to a config file to use. Multiple config files can be specified,
  with values in later files taking precedence. Dafaults to ``None``.

``--debug, -d``
  Print debugging output (set logging level to ``DEBUG`` instead of default
  ``INFO`` level).

``--dhcp_release6``
  Check dhcp_release6 installation

``--dibbler_version``
  Check minimal dibbler version

``--dnsmasq_version``
  Check minimal dnsmasq version

``--ebtables_installed``
  Check ebtables installation

``--icmpv6_header_match``
  Check for ICMPv6 header match support

``--ip6tables_installed``
  Check ip6tables installation

``--iproute2_vxlan``
  Check for iproute2 vxlan support

``--ipset_installed``
  Check ipset installation

``--keepalived_ipv6_support``
  Check keepalived IPv6 support

``--log-config-append PATH, --log_config PATH``
  The name of a logging configuration file. This file is appended to any
  existing logging configuration files. For details about logging
  configuration files, see the Python logging module documentation.
  Note that when logging configuration files are used then all logging
  configuration is set in the configuration file and other logging
  configuration options are ignored (for example,
  ``logging_context_format_string``).

``--log-date-format DATE_FORMAT``
  Format string for %(asctime)s in log records. Default: None.
  This option is ignored if ``log_config_append`` is set.

``--log-dir LOG_DIR, --logdir LOG_DIR``
  (Optional) The base directory used for relative ``log-file`` paths.
  This option is ignored if ``log_config_append`` is set.

``--log-file PATH, --logfile PATH``
  (Optional) Name of log file to output to. If no default is set,
  logging will go to stderr as defined by ``use_stderr``.
  This option is ignored if ``log_config_append`` is set.

``--noarp_header_match``
  The inverse of --arp_header_match

``--noarp_responder``
  The inverse of --arp_responder

``--nobridge_firewalling``
  The inverse of --bridge_firewalling

``--nodebug``
  The inverse of --debug

``--nodhcp_release6``
   The inverse of --dhcp_release6

``--nodibbler_version``
  The inverse of --dibbler_version

``--nodnsmasq_version``
  The inverse of --dnsmasq_version

``--noebtables_installed``
  The inverse of --ebtables_installed

``--noicmpv6_header_match``
  The inverse of --icmpv6_header_match

``--noip6tables_installed``
  The inverse of --ip6tables_installed

``--noip_nonlocal_bind``
  The inverse of --ip_nonlocal_bind

``--noiproute2_vxlan``
  The inverse of --iproute2_vxlan

``--noipset_installed``
  The inverse of --ipset_installed

``--nokeepalived_ipv6_support``
  The inverse of --keepalived_ipv6_support

``--nonova_notify``
  The inverse of --nova_notify

``--noovs_conntrack``
  The inverse of --ovs_conntrack

``--noovs_geneve``
  The inverse of --ovs_geneve

``--noovs_patch``
  The inverse of --ovs_patch

``--noovs_vxlan``
  The inverse of --ovs_vxlan

``--noovsdb_native``
  The inverse of --ovsdb_native

``--noread_netns``
  The inverse of --read_netns

``--nouse-syslog``
  The inverse of --use-syslog

``--nova_notify``
  Check for nova notification support

``--noverbose``
  The inverse of --verbose

``--novf_extended_management``
   The inverse of --vf_extended_management

``--novf_management``
  The inverse of --vf_management

``--nowatch-log-file``
  The inverse of --watch-log-file

``--ovs_geneve``
  Check for OVS Geneve support

``--ovs_patch``
  Check for patch port support

``--ovs_vxlan``
  Check for OVS vxlan support

``--ovsdb_native``
  Check ovsdb native interface support

``--read_netns``
  Check netns permission settings

``--state_path STATE_PATH``
  Where to store Neutron state files. This directory must be writable
  by the agent.

``--syslog-log-facility SYSLOG_LOG_FACILITY``
  Syslog facility to receive log lines.
  This option is ignored if ``log_config_append`` is set.

``--use-syslog``
  Use syslog for logging. Existing syslog format is
  **DEPRECATED** and will be changed later to honor RFC5424.
  This option is ignored if ``log_config_append`` is set.

``--verbose, -v``
  If set to ``false``, the logging level will be set to
  ``WARNING`` instead of the default ``INFO`` level.

``--version``
  show program's version number and exit

``--vf_extended_management``
  Check for VF extended management support

``--vf_management``
  Check for VF management support

``--watch-log-file``
  Uses logging handler designed to watch file system.
  When log file is moved or removed this handler will open a new log
  file with specified path instantaneously. It makes sense only if
  ``log_file`` option is specified and Linux platform is used.
  This option is ignored if ``log_config_append`` is set.


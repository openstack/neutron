# Copyright 2011 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import setuptools
import sys

from quantum.openstack.common import setup

requires = setup.parse_requirements()
depend_links = setup.parse_dependency_links()

if sys.platform == 'win32':
    requires.append('pywin32')
    requires.append('wmi')
    requires.remove('pyudev')

Name = 'quantum'
Url = "https://launchpad.net/quantum"
Version = setup.get_version(Name, '2013.2')
License = 'Apache License 2.0'
Author = 'OpenStack'
AuthorEmail = 'openstack-dev@lists.openstack.org'
Maintainer = ''
Summary = 'Quantum (virtual network service)'
ShortDescription = Summary
Description = Summary

EagerResources = [
    'quantum',
]

config_path = 'etc/quantum/'
init_path = 'etc/init.d'
rootwrap_path = 'etc/quantum/rootwrap.d'
ovs_plugin_config_path = 'etc/quantum/plugins/openvswitch'
bigswitch_plugin_config_path = 'etc/quantum/plugins/bigswitch'
brocade_plugin_config_path = 'etc/quantum/plugins/brocade'
cisco_plugin_config_path = 'etc/quantum/plugins/cisco'
linuxbridge_plugin_config_path = 'etc/quantum/plugins/linuxbridge'
nvp_plugin_config_path = 'etc/quantum/plugins/nicira'
ryu_plugin_config_path = 'etc/quantum/plugins/ryu'
meta_plugin_config_path = 'etc/quantum/plugins/metaplugin'
nec_plugin_config_path = 'etc/quantum/plugins/nec'
hyperv_plugin_config_path = 'etc/quantum/plugins/hyperv'
plumgrid_plugin_config_path = 'etc/quantum/plugins/plumgrid'
midonet_plugin_config_path = 'etc/quantum/plugins/midonet'

if sys.platform == 'win32':
    # Windows doesn't have an "/etc" directory equivalent
    DataFiles = []

    ConsoleScripts = [
        'quantum-hyperv-agent = '
        'quantum.plugins.hyperv.agent.hyperv_quantum_agent:main',
        'quantum-server = quantum.server:main',
        'quantum-db-manage = quantum.db.migration.cli:main',
    ]

    ProjectScripts = []
else:
    DataFiles = [
        (config_path,
            ['etc/quantum.conf',
             'etc/rootwrap.conf',
             'etc/api-paste.ini',
             'etc/policy.json',
             'etc/dhcp_agent.ini',
             'etc/l3_agent.ini',
             'etc/metadata_agent.ini',
             'etc/lbaas_agent.ini']),
        (rootwrap_path,
            ['etc/quantum/rootwrap.d/dhcp.filters',
             'etc/quantum/rootwrap.d/iptables-firewall.filters',
             'etc/quantum/rootwrap.d/l3.filters',
             'etc/quantum/rootwrap.d/linuxbridge-plugin.filters',
             'etc/quantum/rootwrap.d/nec-plugin.filters',
             'etc/quantum/rootwrap.d/openvswitch-plugin.filters',
             'etc/quantum/rootwrap.d/ryu-plugin.filters',
             'etc/quantum/rootwrap.d/lbaas-haproxy.filters']),
        (init_path, ['etc/init.d/quantum-server']),
        (ovs_plugin_config_path,
            ['etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini']),
        (cisco_plugin_config_path,
            ['etc/quantum/plugins/cisco/cisco_plugins.ini']),
        (bigswitch_plugin_config_path,
            ['etc/quantum/plugins/bigswitch/restproxy.ini']),
        (brocade_plugin_config_path,
            ['etc/quantum/plugins/brocade/brocade.ini']),
        (linuxbridge_plugin_config_path,
            ['etc/quantum/plugins/linuxbridge/linuxbridge_conf.ini']),
        (nvp_plugin_config_path,
            ['etc/quantum/plugins/nicira/nvp.ini']),
        (ryu_plugin_config_path, ['etc/quantum/plugins/ryu/ryu.ini']),
        (meta_plugin_config_path,
            ['etc/quantum/plugins/metaplugin/metaplugin.ini']),
        (nec_plugin_config_path, ['etc/quantum/plugins/nec/nec.ini']),
        (hyperv_plugin_config_path,
            ['etc/quantum/plugins/hyperv/hyperv_quantum_plugin.ini']),
        (plumgrid_plugin_config_path,
            ['etc/quantum/plugins/plumgrid/plumgrid.ini']),
        (midonet_plugin_config_path,
            ['etc/quantum/plugins/midonet/midonet.ini']),
    ]

    ConsoleScripts = [
        'quantum-dhcp-agent = quantum.agent.dhcp_agent:main',
        'quantum-dhcp-agent-dnsmasq-lease-update ='
        'quantum.agent.linux.dhcp:Dnsmasq.lease_update',
        'quantum-netns-cleanup = quantum.agent.netns_cleanup_util:main',
        'quantum-l3-agent = quantum.agent.l3_agent:main',
        'quantum-linuxbridge-agent ='
        'quantum.plugins.linuxbridge.agent.linuxbridge_quantum_agent:main',
        'quantum-metadata-agent ='
        'quantum.agent.metadata.agent:main',
        'quantum-ns-metadata-proxy ='
        'quantum.agent.metadata.namespace_proxy:main',
        'quantum-openvswitch-agent ='
        'quantum.plugins.openvswitch.agent.ovs_quantum_agent:main',
        'quantum-ryu-agent = '
        'quantum.plugins.ryu.agent.ryu_quantum_agent:main',
        'quantum-nec-agent = '
        'quantum.plugins.nec.agent.nec_quantum_agent:main',
        'quantum-server = quantum.server:main',
        'quantum-debug = quantum.debug.shell:main',
        'quantum-ovs-cleanup = quantum.agent.ovs_cleanup_util:main',
        'quantum-db-manage = quantum.db.migration.cli:main',
        ('quantum-lbaas-agent = '
         'quantum.plugins.services.agent_loadbalancer.agent:main'),
        ('quantum-check-nvp-config = '
         'quantum.plugins.nicira.nicira_nvp_plugin.check_nvp_config:main'),
    ]

    ProjectScripts = [
        'bin/quantum-rootwrap',
    ]


setuptools.setup(
    name=Name,
    version=Version,
    url=Url,
    author=Author,
    author_email=AuthorEmail,
    description=ShortDescription,
    long_description=Description,
    license=License,
    classifiers=[
        'Environment :: OpenStack',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
    scripts=ProjectScripts,
    install_requires=requires,
    dependency_links=depend_links,
    include_package_data=True,
    setup_requires=['setuptools_git>=0.4'],
    packages=setuptools.find_packages('.'),
    cmdclass=setup.get_cmdclass(),
    data_files=DataFiles,
    eager_resources=EagerResources,
    entry_points={'console_scripts': ConsoleScripts},
)

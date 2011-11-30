try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

import sys
import version

Name = 'quantum'
Url = "https://launchpad.net/quantum"
Version = version.get_git_version()
License = 'Apache License 2.0'
Author = 'Netstack'
AuthorEmail = 'netstack@lists.launchpad.net'
Maintainer = ''
Summary = 'Quantum (virtual network service)'
ShortDescription = Summary
Description = Summary

requires = [
    'eventlet>=0.9.12',
    'Routes>=1.12.3',
    'nose',
    'Paste',
    'PasteDeploy',
    'pep8>=0.6.1',
    'python-gflags',
    'simplejson',
    'sqlalchemy',
    'webob',
    'webtest'
]

EagerResources = [
    'quantum',
]

ProjectScripts = [
]

config_path = 'etc/quantum/'
init_path = 'etc/init.d'
ovs_plugin_config_path = 'etc/quantum/plugins/openvswitch'
cisco_plugin_config_path = 'etc/quantum/plugins/cisco'

print "config_path: %s" % config_path
DataFiles = [
    (config_path,
        ['etc/quantum.conf', 'etc/quantum.conf.test', 'etc/plugins.ini']),
    (init_path, ['etc/init.d/quantum-server']),
    (ovs_plugin_config_path,
        ['etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini']),
    (cisco_plugin_config_path,
        ['etc/quantum/plugins/cisco/credentials.ini',
         'etc/quantum/plugins/cisco/l2network_plugin.ini',
         'etc/quantum/plugins/cisco/nexus.ini',
         'etc/quantum/plugins/cisco/ucs.ini',
         'etc/quantum/plugins/cisco/cisco_plugins.ini',
         'etc/quantum/plugins/cisco/db_conn.ini']),
]

setup(
    name=Name,
    version=Version,
    url=Url,
    author=Author,
    author_email=AuthorEmail,
    description=ShortDescription,
    long_description=Description,
    license=License,
    scripts=ProjectScripts,
    install_requires=requires,
    include_package_data=False,
    packages=find_packages('.'),
    data_files=DataFiles,
    eager_resources=EagerResources,
    entry_points={
        'console_scripts': [
            'quantum-server = quantum.server:main',
            'quantum = quantum.client.cli:main',
        ]
    },
)

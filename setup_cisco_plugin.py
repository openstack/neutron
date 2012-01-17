try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

import sys
from quantum import version

Name = 'quantum-cisco-plugin'
ProjecUrl = ""
Version = version.version_string()
License = 'Apache License 2.0'
Author = 'Cisco Systems'
AuthorEmail = ''
Maintainer = ''
Summary = 'Cisco plugin for Quantum'
ShortDescription = Summary
Description = Summary

requires = [
    'quantum-common',
    'quantum-server',
]

EagerResources = [
    'quantum',
]

ProjectScripts = [
]

PackageData = {
}

# If we're installing server-wide, use an aboslute path for config
# if not, use a relative path
config_path = '/etc/quantum/plugins/cisco'
relative_locations = ['--user', '--virtualenv', '--venv']
if [x for x in relative_locations if x in sys.argv]:
    config_path = 'etc/quantum/plugins/cisco'

DataFiles = [
    (config_path,
    ['etc/quantum/plugins/cisco/credentials.ini',
      'etc/quantum/plugins/cisco/l2network_plugin.ini',
      'etc/quantum/plugins/cisco/nexus.ini',
      'etc/quantum/plugins/cisco/ucs.ini',
      'etc/quantum/plugins/cisco/cisco_plugins.ini',
      'etc/quantum/plugins/cisco/db_conn.ini'])
]

setup(
    name=Name,
    version=Version,
    author=Author,
    author_email=AuthorEmail,
    description=ShortDescription,
    long_description=Description,
    license=License,
    scripts=ProjectScripts,
    install_requires=requires,
    include_package_data=True,
    packages=["quantum.plugins.cisco"],
    package_data=PackageData,
    data_files=DataFiles,
    eager_resources=EagerResources,
    entry_points={
        'console_scripts': [
            'cisco-quantum = quantum.plugins.cisco.client.cli:main'
        ]
    },
)

try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

from quantum import version

import sys

Name = 'quantum-openvswitch-plugin'
ProjecUrl = ""
Version = version.version_string()
License = 'Apache License 2.0'
Author = 'Open vSwitch Team'
AuthorEmail = 'discuss@openvswitch.org'
Maintainer = ''
Summary = 'OpenVSwitch plugin for Quantum'
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
config_path = '/etc/quantum/plugins/openvswitch'
relative_locations = ['--user', '--virtualenv', '--venv']
if [x for x in relative_locations if x in sys.argv]:
    config_path = 'etc/quantum/plugins/openvswitch'

DataFiles = [
    (config_path,
    ['etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini'])
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
    packages=["quantum.plugins.openvswitch"],
    package_data=PackageData,
    data_files=DataFiles,
    eager_resources=EagerResources,
)

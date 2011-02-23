try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

import os
import sys

Name = 'quantum-server'
Url = "https://launchpad.net/quantum"
Version = '2012.1-dev'
License = 'Apache License 2.0'
Author = 'Netstatck'
AuthorEmail = 'netstack@lists.launchpad.net'
Maintainer = ''
Summary = 'Server functionalities for Quantum'
ShortDescription = Summary
Description = Summary

requires = [
    'quantum-common'
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
config_path = '/etc/quantum/'
init_path = '/etc/init.d'

relative_locations = ['--user', '--virtualenv', '--venv']
if [x for x in relative_locations if x in sys.argv]:
    config_path = 'etc/quantum/'
    init_path = 'etc/init.d'

DataFiles = [
    (config_path,
    ['etc/quantum.conf', 'etc/quantum.conf.sample',
     'etc/quantum.conf.test', 'etc/plugins.ini']),
    (init_path, ['etc/init.d/quantum-server'])
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
    include_package_data=True,
    packages=find_packages('lib'),
    package_data=PackageData,
    data_files=DataFiles,
    package_dir={'': 'lib'},
    eager_resources=EagerResources,
    namespace_packages=['quantum'],
    entry_points={
        'console_scripts': [
            'quantum-server = quantum.server:main'
        ]
    },
)

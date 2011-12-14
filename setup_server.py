try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

import os
import sys
import version

Name = 'quantum-server'
Url = "https://launchpad.net/quantum"
Version = version.get_git_version()
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
config_path = '/etc/quantum'
init_path = '/etc/init.d'

relative_locations = ['--user', '--virtualenv', '--venv']
if [x for x in relative_locations if x in sys.argv]:
    config_path = 'etc/quantum/'
    init_path = 'etc/init.d'

import os
from distutils.command.build_py import build_py as _build_py


class build_py(_build_py):
    def find_data_files(self, package, src_dir):
        files = []
        for p in _build_py.find_data_files(self, package, src_dir):
            if os.path.isdir(p):
                files.extend(os.path.join(par, f)
                             for par, dirs, files in os.walk(p)
                             for f in files)
            else:
                files.append(p)
        return files

print "config_path: %s" % config_path
DataFiles = [
    (config_path,
        ['etc/quantum.conf', 'etc/quantum.conf.test', 'etc/plugins.ini']),
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
    packages=["quantum.server"],
    package_data=PackageData,
    data_files=DataFiles,
    package_dir={'quantum': 'quantum'},
    eager_resources=EagerResources,
    entry_points={
        'console_scripts': [
            'quantum-server = quantum.server:main'
        ]
    },
)

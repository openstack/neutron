try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

import version

Name = 'quantum-common'
Url = "https://launchpad.net/quantum"
Version = version.get_git_version()
License = 'Apache License 2.0'
Author = 'Netstack'
AuthorEmail = 'netstack@lists.launchpad.net'
Maintainer = ''
Summary = 'Common functionalities for Quantum'
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

PackageData = {
}

exclude = ['quantum.client', 'quantum.client.*', 'quantum.server',
    'quantum.server.*', 'quantum.tests', 'quantum.tests.*',
    'quantum.plugins.*', 'quantum.plugins']
pkgs = find_packages('.', exclude=exclude)
pkgs = filter(lambda x: x.startswith("quantum"), pkgs)

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
    packages=pkgs,
    package_data=PackageData,
    eager_resources=EagerResources,
    entry_points={},
)

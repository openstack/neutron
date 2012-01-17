try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

from quantum import version
import sys

Name = 'quantum-sample-plugin'
Summary = 'Sample plugin for Quantum'
Url = "https://launchpad.net/quantum"
Version = version.version_string()
License = 'Apache License 2.0'
Author = 'Netstack'
AuthorEmail = 'netstack@lists.launchpad.net'
Maintainer = ''
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
    packages=["quantum.plugins.sample"],
    package_data=PackageData,
    eager_resources=EagerResources,
)

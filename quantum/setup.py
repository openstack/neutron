try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

Name = 'quantum'
Url = "https://launchpad.net/quantum"
Version = '2012.1-dev'
License = 'Apache License 2.0'
Author = 'Netstack'
AuthorEmail = 'netstack@lists.launchpad.net'
Maintainer = ''
Summary = 'Layer 2 network as a service for Openstack'
ShortDescription = Summary
Description = Summary

requires = [
    'quantum-common',
    'quantum-client',
    'quantum-server'
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
    url=Url,
    author=Author,
    author_email=AuthorEmail,
    description=ShortDescription,
    long_description=Description,
    license=License,
    scripts=ProjectScripts,
    install_requires=requires,
    include_package_data=True,
    package_data=PackageData,
)

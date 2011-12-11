try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

import version

Name = 'quantum-client'
Url = "https://launchpad.net/quantum"
Version = version.get_git_version()
License = 'Apache License 2.0'
Author = 'Netstack'
AuthorEmail = 'netstack@lists.launchpad.net'
Maintainer = ''
Summary = 'Client functionalities for Quantum'
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
    packages=["quantum.client"],
    package_data=PackageData,
    eager_resources=EagerResources,
    entry_points={
        'console_scripts': [
            'quantum = quantum.client.cli:main'
        ]
    },
)

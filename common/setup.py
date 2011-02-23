try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

Name = 'quantum-common'
Url = "https://launchpad.net/quantum"
Version = '2012.1-dev'
License = 'Apache License 2.0'
# Change as required
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
    package_dir={'': 'lib'},
    eager_resources=EagerResources,
    namespace_packages=['quantum'],
    entry_points={
        'console_scripts': [
            'quantum-tests = quantum.run_tests:main'
        ]
    },
)

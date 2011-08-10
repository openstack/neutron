import os
import sys
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()
    
requirements = ['httplib2','eventlet','routes','webob']

setup(
    name = "Quantum",
    version = "0.1",
    description = "Layer 2 network as a service for Openstack",
    long_description = read('README'),
    url = 'http://launchpad.net/quantum',
    license = 'Apache',
    author = 'Netstack',
    author_email = 'netstack@launchpad.net',
    packages = find_packages(exclude=['tests']),
    classifiers = [
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
    namespace_packages = ["quantum"],
    install_requires = requirements,
    
    tests_require = ["nose"],
    test_suite = "nose.collector",
)

# Copyright (c) 2010 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Neutron documentation build configuration file

import logging
import os
import sys

# NOTE(amotoki): In case of oslo_config.sphinxext is enabled,
# when resolving automodule neutron.tests.functional.db.test_migrations,
# sphinx accesses tests/functional/__init__.py is processed,
# eventlet.monkey_patch() is called and monkey_patch() tries to access
# pyroute2.common.__class__ attribute. It raises pyroute2 warning and
# it causes sphinx build failure due to warning-is-error = 1.
# To pass sphinx build, ignore pyroute2 warning explicitly.
logging.getLogger('pyroute2').setLevel(logging.ERROR)

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
NEUTRON_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
sys.path.insert(0, NEUTRON_DIR)

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.coverage',
    'sphinx.ext.ifconfig',
    'sphinx.ext.graphviz',
    'sphinx.ext.todo',
    'openstackdocstheme',
    'sphinx_feature_classification.support_matrix',
    'oslo_config.sphinxext',
    'oslo_config.sphinxconfiggen',
    'oslo_policy.sphinxext',
    'oslo_policy.sphinxpolicygen',
]

# Project cross-reference roles
openstackdocs_projects = [
    'neutron',
    'nova',
]

# openstackdocstheme options
openstackdocs_repo_name = 'openstack/neutron'
openstackdocs_pdf_link = True
openstackdocs_bug_project = 'neutron'
openstackdocs_bug_tag = 'doc'
openstackdocs_auto_name = False

todo_include_todos = True

# The suffix of source filenames.
source_suffix = '.rst'

# The master toctree document.
master_doc = 'index'

# General information about the project.
project = 'Neutron'
copyright = '2011-present, OpenStack Foundation.'

# If true, sectionauthor and moduleauthor directives will be shown in the
# output. They are ignored by default.
show_authors = True

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'native'

# A list of ignored prefixes for module index sorting.
modindex_common_prefix = ['neutron.']

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  Major themes that come with
# Sphinx are currently 'default' and 'sphinxdoc'.
# html_theme_path = ["."]
# html_theme = '_theme'
html_theme = 'openstackdocs'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']


# -- Options for LaTeX output ------------------------------------------------

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title, author,
# documentclass [howto/manual]).
latex_documents = [
    ('pdf-index', 'doc-neutron.tex', 'Neutron Documentation',
     'Neutron development team', 'manual'),
]

# Disable usage of xindy https://bugzilla.redhat.com/show_bug.cgi?id=1643664
latex_use_xindy = False

latex_domain_indices = False

latex_elements = {
    'makeindex': '',
    'printindex': '',
    'preamble': r'\setcounter{tocdepth}{3}',
}

# -- Options for oslo_config.sphinxconfiggen ---------------------------------

_config_generator_config_files = [
    'dhcp_agent.ini',
    'l3_agent.ini',
    'macvtap_agent.ini',
    'metadata_agent.ini',
    'metering_agent.ini',
    'ml2_conf.ini',
    'neutron.conf',
    'openvswitch_agent.ini',
    'sriov_agent.ini',
]


def _get_config_generator_config_definition(conf):
    config_file_path = '../../etc/oslo-config-generator/%s' % conf
    # oslo_config.sphinxconfiggen appends '.conf.sample' to the filename,
    # strip file extentension (.conf or .ini).
    output_file_path = '_static/config-samples/%s' % conf.rsplit('.', 1)[0]
    return (config_file_path, output_file_path)


config_generator_config_file = [
    _get_config_generator_config_definition(conf)
    for conf in _config_generator_config_files
]

# -- Options for oslo_policy.sphinxpolicygen ---------------------------------

policy_generator_config_file = '../../etc/oslo-policy-generator/policy.conf'
sample_policy_basename = '_static/neutron'

linkcheck_anchors_ignore = [
    # skip gerrit anchors
    r'\/q\/.*',
    r'q\,.*',
    r'\/c\/.*'
]

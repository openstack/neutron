================
Policy Reference
================

.. warning::

   JSON formatted policy file is deprecated since Neutron 18.0.0 (Wallaby).
   This `oslopolicy-convert-json-to-yaml`__ tool will migrate your existing
   JSON-formatted policy file to YAML in a backward-compatible way.

.. __: https://docs.openstack.org/oslo.policy/latest/cli/oslopolicy-convert-json-to-yaml.html

Neutron, like most OpenStack projects, uses a policy language to restrict
permissions on REST API actions.

The following is an overview of all available policies in neutron.

.. only:: html

   For a sample policy file, refer to :doc:`/configuration/policy-sample`.

   .. toctree::
      :hidden:

      policy-sample

.. show-policy::
      :config-file: etc/oslo-policy-generator/policy.conf

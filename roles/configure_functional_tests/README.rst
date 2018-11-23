Configure host to run on it Neutron functional/fullstack tests

**Role Variables**

.. zuul:rolevar:: tests_venv
   :default: {{ tox_envlist }}

.. zuul:rolevar:: base_dir
   :default: {{ ansible_user_dir }}/src/git.openstack.org

.. zuul:rolevar:: gate_dest_dir
   :default: {{ base_dir }}/openstack

.. zuul:rolevar:: devstack_dir
   :default: {{ base_dir }}/openstack-dev/devstack

.. zuul:rolevar:: neutron_dir
   :default: {{ gate_dest_dir }}/neutron

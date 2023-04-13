---
config:
    entry_point: ./tools/ovn_migration/infrared/tripleo-ovn-migration/main.yml
    plugin_type: install
subparsers:
    tripleo-ovn-migration:
        description: Migrate an existing TripleO overcloud from Neutron ML2OVS plugin to OVN
        include_groups: ["Ansible options", "Inventory", "Common options", "Answers file"]
        groups:
            - title: Containers
              options:
                  registry-namespace:
                      type: Value
                      help: The alternative docker registry namespace to use for deployment.

                  registry-prefix:
                      type: Value
                      help: The images prefix

                  registry-tag:
                      type: Value
                      help: The images tag

                  registry-mirror:
                      type: Value
                      help: The alternative docker registry to use for deployment.

            - title: Deployment Description
              options:
                  version:
                      type: Value
                      help: |
                          The product version
                          Numbers are for OSP releases
                          Names are for RDO releases
                          If not given, same version of the undercloud will be used
                      choices:
                        - "7"
                        - "8"
                        - "9"
                        - "10"
                        - "11"
                        - "12"
                        - "13"
                        - "14"
                        - "15"
                        - "16"
                        - "16.1"
                        - "16.2"
                        - kilo
                        - liberty
                        - mitaka
                        - newton
                        - ocata
                        - pike
                        - queens
                        - rocky
                        - stein
                        - train
                  install_from_package:
                      type: Bool
                      help: Install openstack-neutron-ovn-migration-tool rpm
                      default: True

                  dvr:
                      type: Bool
                      help: If the deployment is to be dvr or not
                      default: False

                  create_resources:
                      type: Bool
                      help: Create resources to measure downtime
                      default: True

                  external_network:
                      type: Value
                      help: External network name to use
                      default: public

                  image_name:
                      type: Value
                      help: Image name to use
                      default: cirros-0.3.5-x86_64-disk.img

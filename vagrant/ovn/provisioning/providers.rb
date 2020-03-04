
def provider_box(provider)
    distro = ENV.fetch('DISTRO', 'ubuntu')
    boxes = YAML.load_file('../provisioning/boxes.yml')[distro]

    # we can always override the box via the VAGRANT_OVN_VM_BOX
    # environment variable
    return ENV.fetch('VAGRANT_OVN_VM_BOX', boxes[provider])
end

def configure_providers(vm, config)
    vm.provider 'virtualbox' do |vb, cfg|
       cfg.vm.box = provider_box('virtualbox')
       vb.memory = config['memory']
       vb.cpus = config['cpus']
       vb.customize [
           'modifyvm', :id,
           '--nicpromisc3', "allow-all"
          ]
       vb.customize [
           "guestproperty", "set", :id,
           "/VirtualBox/GuestAdd/VBoxService/--timesync-set-threshold", 10000
          ]
    end

    vm.provider 'parallels' do |vb, cfg|
       cfg.vm.box = provider_box('parallels')
       vb.memory = config['memory']
       vb.cpus = config['cpus']
       vb.customize ['set', :id, '--nested-virt', 'on']
    end

    vm.provider 'libvirt' do |vb, cfg|
       cfg.vm.box = provider_box('libvirt')
       vb.memory = config['memory']
       vb.cpus = config['cpus']
       vb.nested = true
       vb.graphics_type = 'spice'
       vb.video_type = 'qxl'
       vb.suspend_mode = 'managedsave'
    end
end

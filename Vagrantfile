# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # Host tmux source: always use ~/.tmux.conf on the host
  tmux_host_file = File.expand_path("~/.tmux.conf")

  # Helper: if host tmux file exists, upload it to guest ~/.tmux.conf and fix ownership
  define_provision_tmux = lambda do |vm|
    next unless File.exist?(tmux_host_file)

    # Upload host ~/.tmux.conf -> guest /home/vagrant/.tmux.conf
    vm.vm.provision "file", source: tmux_host_file, destination: "/home/vagrant/.tmux.conf"

    # Ensure correct ownership and permissions for the vagrant user
    vm.vm.provision "shell", inline: <<-SHELL
      chown vagrant:vagrant /home/vagrant/.tmux.conf || true
      chmod 644 /home/vagrant/.tmux.conf || true
      echo 'Copied host ~/.tmux.conf to /home/vagrant/.tmux.conf'
    SHELL
  end

  config.vm.define "test1" do |test1|
    test1.vm.box = "bento/ubuntu-24.04"
    test1.vm.synced_folder "./", "/vagrant", type: "rsync", rsync__exclude: ["tracer/target","checkouts","repos","lazyfs/tmp","rw/Anduril/"]
    test1.vm.synced_folder "~/shared/test1/", "/shared", type: "virtualbox"
    test1.disksize.size = '60GB'
    test1.vm.provider "virtualbox" do |v|
      v.cpus = 2
      v.memory = "8192"
    end

    # Provision tmux config from host to guest ~/.tmux.conf
    define_provision_tmux.call(test1)
  end

  config.vm.define "test2" do |test2|
    test2.vm.box = "bento/ubuntu-24.04"
    test2.vm.synced_folder "./", "/vagrant", type: "rsync", rsync__exclude: ["tracer/target","build","repos"]
    test2.vm.synced_folder "~/shared/test2/", "/shared", type: "virtualbox"
    test2.disksize.size = '60GB'
    test2.vm.provider "virtualbox" do |v|
      v.cpus = 4
      v.memory = "8192"
    end

    # Provision tmux config from host to guest ~/.tmux.conf
    define_provision_tmux.call(test2)
  end

  config.vm.define "test3" do |test3|
    test3.vm.box = "bento/ubuntu-24.04"
    test3.vm.synced_folder "./", "/vagrant", type: "rsync", rsync__exclude: ["tracer/target","build","repos"]
    test3.vm.synced_folder "~/shared/test3/", "/shared", type: "virtualbox"
    test3.disksize.size = '60GB'
    test3.vm.provider "virtualbox" do |v|
      v.cpus = 16
      v.memory = "30000"
    end

    # Provision tmux config from host to guest ~/.tmux.conf
    define_provision_tmux.call(test3)
  end
end

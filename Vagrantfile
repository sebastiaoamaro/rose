# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
    config.vm.define "test1" do |test1|
        test1.vm.box = "bento/ubuntu-24.04"
        test1.vm.synced_folder "./", "/vagrant", type: "rsync",rsync__exclude: ["target","build"]
        test1.vm.synced_folder "~/vagrant_synced_folder", "/shared",type:"rsync"
        test1.disksize.size = '128GB'
        test1.vm.provider "virtualbox" do |v|
            v.cpus = 4        # Set number of CPUs
            v.memory = "8192"
        end
    end

    config.vm.define "test2" do |test2|
        test2.vm.box = "bento/ubuntu-24.04"
        test2.vm.synced_folder "./", "/vagrant", type: "rsync",rsync__exclude: ["target","build","ycsb-0.17.0"]
        test2.vm.synced_folder "~/vagrant_synced_folder", "/shared",type:"rsync"
        test2.disksize.size = '128GB'
        test2.vm.provider "virtualbox" do |v|
            v.cpus = 4        # Set number of CPUs
            v.memory = "8192"
        end
    end

    config.vm.define "test3" do |test3|
        test3.vm.box = "bento/ubuntu-24.04"
        test3.vm.synced_folder "./", "/vagrant", type: "rsync",rsync__exclude: ["target","build","ycsb-0.17.0","Anduril"]
        test3.vm.synced_folder "~/vagrant_synced_folder", "/shared",type:"rsync"
        test3.vm.provider "virtualbox" do |v|
            v.cpus = 1        # Set number of CPUs
            v.memory = "4096"
        end
    end

    config.vm.define "remote" do |remote|
        remote.vm.box = "bento/ubuntu-24.04"
        remote.vm.synced_folder "./", "/vagrant",type:"virtualbox"
        remote.disksize.size = '128GB'
        remote.vm.provider "virtualbox" do |v|
            v.cpus = 16        # Set number of CPUs
            v.memory = "16384"
        end
    end
end

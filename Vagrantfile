# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
    config.vm.define "test1" do |test1|
        test1.vm.box = "bento/ubuntu-24.04"
        test1.vm.synced_folder "./", "/vagrant", type: "rsync",rsync__exclude: ["tracer/target","checkouts","build","repos","tests/bugdetection/redisraft/*","lazyfs/tmp","rw/Anduril/"]
        test1.vm.synced_folder "~/shared/test1/", "/shared",type:"virtualbox"
        test1.disksize.size = '60GB'
        test1.vm.provider "virtualbox" do |v|
            v.cpus = 8        # Set number of CPUs
            v.memory = "8192"
        end
    end

    config.vm.define "test2" do |test2|
        test2.vm.box = "bento/ubuntu-24.04"
        test2.vm.synced_folder "./", "/vagrant", type: "rsync",rsync__exclude: ["tracer/target","build","repos"]
        test2.vm.synced_folder "~/shared/test2/", "/shared",type:"virtualbox"
        test2.disksize.size = '60GB'
        test2.vm.provider "virtualbox" do |v|
            v.cpus = 4       # Set number of CPUs
            v.memory = "8192"
        end
    end

    config.vm.define "test3" do |test3|
        test3.vm.box = "bento/ubuntu-24.04"
        test3.vm.synced_folder "./", "/vagrant", type: "rsync",rsync__exclude: ["tracer/target","build","repos"]
        test3.vm.synced_folder "~/shared/test3/", "/shared",type:"virtualbox"
        test3.disksize.size = '60GB'
        test3.vm.provider "virtualbox" do |v|
            v.cpus = 16       # Set number of CPUs
            v.memory = "30000"
        end
    end
end

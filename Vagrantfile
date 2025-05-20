# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
    config.vm.define "test1" do |test1|
        test1.vm.box = "bento/ubuntu-24.04"
        test1.vm.synced_folder "./", "/vagrant", type: "rsync",rsync__exclude: ["target","build","repos","temp_sched.yaml","tests/bugdetection/redisraft/*"]
        test1.vm.synced_folder "~/shared/test1/", "/shared",type:"virtualbox"
        test1.disksize.size = '128GB'
        test1.vm.provider "virtualbox" do |v|
            v.cpus = 4        # Set number of CPUs
            v.memory = "8192"
        end
    end

    config.vm.define "test2" do |test2|
        test2.vm.box = "bento/ubuntu-24.04"
        test2.vm.synced_folder "./", "/vagrant", type: "rsync",rsync__exclude: ["target","build","repos","ycsb-0.17.0","temp_sched.yaml"]
        test2.vm.synced_folder "~/shared/test2/", "/shared",type:"virtualbox"
        test2.disksize.size = '128GB'
        test2.vm.provider "virtualbox" do |v|
            v.cpus = 4       # Set number of CPUs
            v.memory = "8192"
        end
    end

    config.vm.define "test3" do |test3|
        test3.vm.box = "bento/ubuntu-24.04"
        test3.vm.synced_folder "./", "/vagrant", type: "rsync",rsync__exclude: ["target","build","repos","ycsb-0.17.0","Anduril","temp_sched.yaml"]
        test3.vm.synced_folder "~/shared/test3/", "/shared",type:"virtualbox"
        test3.vm.provider "virtualbox" do |v|
            v.cpus = 4        # Set number of CPUs
            v.memory = "4096"
        end
    end

    config.vm.define "remote1" do |remote1|
        remote1.vm.box = "bento/ubuntu-24.04"
        remote1.vm.synced_folder "./", "/vagrant", type: "rsync",rsync__exclude: ["target","repos","build","Anduril",
        "schedules/tracing_tests/redis/traces","tests/bugdetection/redisraft/*","temp_sched.yaml"]
        remote1.vm.synced_folder "~/shared/remote1/", "/shared",type:"virtualbox"
        remote1.vm.provider "virtualbox" do |v|
            v.cpus = 16       # Set number of CPUs
            v.memory = "20000"
        end
    end
    config.vm.define "remote2" do |remote2|
        remote2.vm.box = "bento/ubuntu-24.04"
        remote2.vm.synced_folder "./", "/vagrant", type: "rsync",rsync__exclude: ["target","build","repos","ycsb-0.17.0","Anduril",
        "schedules/tracing_tests/redis/traces","tests/bugdetection/redisraft/*","temp_sched.yaml"]
        remote2.vm.synced_folder "~/shared/remote2/", "/shared",type:"virtualbox"
        remote2.disksize.size = '40GB'
        remote2.vm.provider "virtualbox" do |v|
            v.cpus = 8        # Set number of CPUs
            v.memory = "16388"
        end
    end

end

# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
    config.vm.define "test1" do |test1|
        test1.vm.box = "bento/ubuntu-24.04"
        test1.vm.synced_folder "./", "/vagrant", type: "rsync",rsync__exclude: ["tracer/target","checkouts","build","repos","tests/bugdetection/redisraft/*","lazyfs/tmp","rw/Anduril/*"]
        test1.vm.synced_folder "~/shared/test1/", "/shared",type:"virtualbox"
        test1.disksize.size = '128GB'
        test1.vm.network "private_network", ip: "192.168.56.10"
        test1.vm.provider "virtualbox" do |v|
            v.cpus = 4        # Set number of CPUs
            v.memory = "8192"
        end
    end

    config.vm.define "test2" do |test2|
        test2.vm.box = "bento/ubuntu-24.04"
        test2.vm.synced_folder "./", "/vagrant", type: "rsync",rsync__exclude: ["tracer/target","build","repos","rw/Anduril/*"]
        test2.vm.synced_folder "~/shared/test2/", "/shared",type:"virtualbox"
        test2.disksize.size = '128GB'
        test2.vm.provider "virtualbox" do |v|
            v.cpus = 4       # Set number of CPUs
            v.memory = "8192"
        end
    end

    config.vm.define "test3" do |test3|
        test3.vm.box = "bento/ubuntu-24.04"
        test3.vm.synced_folder "./", "/vagrant", type: "rsync",rsync__exclude: ["tracer/target","build","repos","rw/Anduril/*"]
        test3.vm.synced_folder "~/shared/test3/", "/shared",type:"virtualbox"
        test3.disksize.size = '128GB'
        test3.vm.provider "virtualbox" do |v|
            v.cpus = 4       # Set number of CPUs
            v.memory = "8192"
        end
    end

    config.vm.define "test4" do |test4|
        test4.vm.box = "bento/ubuntu-24.04"
        test4.vm.synced_folder "./", "/vagrant", type: "rsync",rsync__exclude: ["tracer/target","build","repos","rw/Anduril/*"]
        test4.vm.synced_folder "~/shared/test4/", "/shared",type:"virtualbox"
        test4.vm.provider "virtualbox" do |v|
            v.cpus = 4       # Set number of CPUs
            v.memory = "8192"
        end
    end

    config.vm.define "remote1" do |remote1|
        remote1.vm.box = "bento/ubuntu-24.04"
        remote1.vm.synced_folder "./", "/vagrant", type: "rsync",rsync__exclude: ["tracer/target","repos","build","Anduril",
        "schedules/tracing_tests/redis/traces","tests/bugdetection/redisraft/*","temp_sched.yaml"]
        remote1.vm.synced_folder "~/shared/remote1/", "/shared",type:"virtualbox"
        remote1.vm.provider "virtualbox" do |v|
            v.cpus = 16      # Set number of CPUs
            v.memory = "30000"
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

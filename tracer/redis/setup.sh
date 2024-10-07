        sudo /home/sebastiaoamaro/phd/torefidevel/tests/redis/configs/setup.sh $1
        docker compose -f /home/sebastiaoamaro/phd/torefidevel/tests/redis/configs/docker-compose$1.yaml up -d
        sleep 15
        redis-cli --cluster create $(cat /home/sebastiaoamaro/phd/torefidevel/tests/redis/configs/ips$1.txt) --cluster-yes
        sleep 15
function machineCREATE() {


    eval $(docker-machine env -u)
    docker-machine create --driver virtualbox manager1
    docker-machine create --driver virtualbox manager2
    docker-machine create --driver virtualbox manager3
    docker-machine create --driver virtualbox worker1.1
    docker-machine create --driver virtualbox worker1.2
    docker-machine create --driver virtualbox worker2.1
    docker-machine create --driver virtualbox worker2.2
    docker-machine create --driver virtualbox worker3.1
    docker-machine create --driver virtualbox worker3.2

eval $(docker-machine env -u)
    docker-machine restart  manager1
    docker-machine restart  manager2
    docker-machine restart  manager3
    docker-machine restart  worker1.1
    docker-machine restart  worker1.2
    docker-machine restart  worker2.1
    docker-machine restart  worker2.2
    docker-machine restart  worker3.1
    docker-machine restart  worker3.2
    
        docker-machine stop  manager1
    docker-machine stop  manager2
    docker-machine stop  manager3
    docker-machine stop  worker1.1
    docker-machine stop  worker1.2
    docker-machine stop  worker2.1
    docker-machine stop  worker2.2
    docker-machine stop  worker3.1
    docker-machine stop  worker3.2
    eval $(docker-machine env -u)
}

function manualProcess() {

    eval $(docker-machine env manager1)
    docker swarm init --advertise-addr eth1
    docker swarm join-token manager
    docker swarm join-token worker

    eval $(docker-machine env manager2)
    docker swarm join --token SWMTKN-1-5f3q1f6sztvm6occ8uwksxovv9w0xz8jrwor7owhyo970ii2fa-c7ezwjrje0hh2fxhm3fyn2d0g 192.168.99.139:2377

    eval $(docker-machine env manager3)
    docker swarm join --token SWMTKN-1-5f3q1f6sztvm6occ8uwksxovv9w0xz8jrwor7owhyo970ii2fa-c7ezwjrje0hh2fxhm3fyn2d0g 192.168.99.139:2377


    eval $(docker-machine env worker1.1)
    #paste docker swarm join-token worker code
    eval $(docker-machine env worker1.2)
    #paste docker swarm join-token worker code



    eval $(docker-machine env worker2.1)
    #paste docker swarm join-token worker code
    eval $(docker-machine env worker2.2)
    #paste docker swarm join-token worker code





    eval $(docker-machine env worker3.1)
    #paste docker swarm join-token worker code
    eval $(docker-machine env worker3.2)
    #paste docker swarm join-token worker code

    docker service create --name registry --publish published=5000,target=5000 registry:2

    eval $(docker-machine env manager1)

    docker build -t moonbird .
    docker service create --name registry --publish published=5000,target=5000 registry:2

    docker-compose -f docker-compose.yml build
    docker-compose -f docker-compose.yml push

    docker stack deploy --compose-file docker-compose.yml moonbird


    }


function foo() {
    
}



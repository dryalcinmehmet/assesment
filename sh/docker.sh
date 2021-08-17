# makineye bağlanmak için
eval $(docker-machine env machine-name)
# geri çıkmak için aşağıdaki
eval $(docker-machine env -u)


# docker machine ve swarm kurulumu

docker-machine create --driver virtualbox manager
docker-machine create --driver virtualbox worker1
docker-machine create --driver virtualbox worker2
docker-machine create --driver virtualbox worker3
eval $(docker-machine env manager)
docker swarm init # it gives ip adress copy that and
docker swarm init --advertise-addr 192.168.99.109
#than copy giving code like below
docker swarm join --token SWMTKN-1-5npyn33vxfx0kxmg75qpgbhv23te3nhxs9r56p5ptnare6pnqc-8n6dzp1r1i8qnnsbfw5k1p02e 192.168.99.109:2377

eval $(docker-machine env worker1)
#paste worker link above
eval $(docker-machine env worker2)
#paste worker link above
eval $(docker-machine env worker3)
#paste worker link above
docker service create --name registry --publish published=5000,target=5000 registry:2

eval $(docker-machine env manager)

docker build -t moonbird .
docker-compose -f docker-compose.yml build
docker-compose -f docker-compose.yml push

docker stack deploy --compose-file docker-compose.yml moonbird



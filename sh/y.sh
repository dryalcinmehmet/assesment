#!/bin/bash

function restart() {

    redis-cli FLUSHALL
    redis-cli FLUSHALL ASYNC

    systemctl restart nginx
    systemctl restart gunicorn
}

function killpostgres() {
    sudo -i -u postgres psql -c """SELECT pg_terminate_backend(pg_stat_activity.pid)
                                FROM pg_stat_activity
                                WHERE datname = 'test'
                                AND pid <> pg_backend_pid();"""
}

function restart() {

    aws s3 ls s3://bucket-name
    than type aws credintials
    aws s3 mb s3://new-bucket
    aws s3 cp /home/doctor/Downloads/test/ s3://corporate-cognitus-bookmark --recursive

}

function clone() {

    function set() {

        cd cognitus-web &&
            git pull &&
            get fetch --all &&
            git config --global core.fileMode false &&
            git config core.fileMode false &&
            chmod 777 * -R &&
            git status &&
            echo "yes" | python manage.py collectstatic &&
            bash --rcfile "/home/doctor/Desktop/works/env/bin/activate" -i &&
            exec bash
    }

    git reset &&
        git init &&
        git clone --single-branch --branch "$1" https://bitbucket.etiya.com/scm/ser/generic_search.git || echo "Folder exist." &&
        set

}

function zemberek() {

    #  docker login --username dryalcinmehmet
    #  3e4ccf74-8ec8-41c1-9317-d8c3dce8553c

    git clone https://github.com/cbilgili/zemberek-nlp-server.git
    cd zemberek-nlp-server
    mvn clean install
    docker build -t zemberek-nlp-server .
    docker run -p 4567:4567 zemberek-nlp-server

}

function minio() {
    docker run -p 9000:9000 \
        -e "MINIO_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE" \
        -e "MINIO_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
        minio/minio server /data
}

function gm() {

    git clone https://bitbucket.etiya.com/scm/ser/cognitus-web.git || echo "ok" &&
        cd cognitus-web || echo "ok" &&
        git pull || echo "ok" &&
        get fetch --all || echo "ok" &&
        git config --global core.fileMode false || echo "ok" &&
        git config core.fileMode false || echo "ok" &&
        chmod 777 * -R &&
        git status

}

function ypush() {

    git status
    git add --all
    git commit -m "$1"
    git push origin HEAD
}

function us() {
    python manage.py migrate || echo "ok" &&
    chmod 777 * -R || echo "ok" &&
    python manage.py createsuperuser --user admin --email admin@admin.com
    echo "mehmet99"
}

function cont() {

    docker exec -it --user root $1 bash

}
function elastic() {

    docker pull docker.elastic.co/elasticsearch/elasticsearch:7.10.1

    docker run -p 9200:9200 -p 9300:9300 -e "discovery.type=single-node" docker.elastic.co/elasticsearch/elasticsearch:7.10.1

}
function m() {
    python manage.py makemigrations
    python manage.py migrate
}
function co() {

    git checkout "$1" || echo "ok" &&
        git pull --all || echo "ok" &&
        git fetch --all || echo "ok" &&
        git config --global core.fileMode false || echo "ok" &&
        git config core.fileMode false || echo "ok" &&
        chmod 777 * -R &&
        git status &&
        git branch &&
        exec bash

}
function foo() {
     git config --global core.fileMode false
        git config core.fileMode false
}
function change_msg() {
    git commit --amend
    git push --force-with-lease https://bitbucket.etiya.com/scm/ser/cognitus-web.git "$1"
}

function remove() {
    dpkg -l | grep -i docker

    sudo apt-get purge -y docker-engine docker docker.io docker-ce docker-ce-cli
    sudo apt-get autoremove -y --purge docker-engine docker docker.io docker-ce

    sudo rm -rf /var/lib/docker /etc/docker
    sudo rm /etc/apparmor.d/docker
    sudo groupdel docker
    sudo rm -rf /var/run/docker.sock

}
function branch() {
        git pull --all || echo "ok" &&
        git fetch --all || echo "ok" &&
        git checkout -b "$1" || echo "ok" &&
        git checkout "$1" || echo "ok" &&
        git status || echo "ok" &&
        git config --global core.fileMode false || echo "ok" &&
        git config core.fileMode false || echo "ok" &&
        chmod 777 * -R &&
        git status &&
        exec bash

}

function cl() {
    kill -9 $(ps aux | grep celery | grep -v grep | awk '{print $2}' | tr '\n' ' ') >/dev/null 2>&1 &&
        kill -9 $(ps aux | grep celery | grep -v grep | awk '{print $2}' | tr '\n' ' ') >/dev/null 2>&1 &&
        kill -9 $(ps aux | grep celery | grep -v grep | awk '{print $2}' | tr '\n' ' ') >/dev/null 2>&1 &&
        kill -9 $(ps aux | grep celery | grep -v grep | awk '{print $2}' | tr '\n' ' ') >/dev/null 2>&1

}

function start() {

    git rebase release/1.12

    #git checkout aq
    #git merge master

    #master to branch merge
    #git checkout branch
    #git merge master

    #rollback uncommitted merge
    #git merge --abort

    #branch to master merge
    #git checkout master
    #git merge branch_name
}

function csv() {

    PGDATABASE=bookmark
    PGUSER=cognitus_corp
    PGSCHEMA=cognitus_corp
    PGHOST=seyhan.cogxxz15eccf.ca-central-1.rds.amazonaws.com
    echo " Schema Name is-->$PGSCHEMA   Database Name--> $PGDATABASE   User Name-->$PGUSER"

    sudo psql -U $PGUSER -h $PGHOST -Atc "select tablename from pg_tables where schemaname='$PGSCHEMA'" $PGDATABASE |
        while read TABLENAME; do
            echo "$TABLENAME"
            psql -U $PGUSER -h $PGHOST --no-password -c "COPY $PGSCHEMA.$TABLENAME TO STDOUT WITH CSV HEADER" $PGDATABASE >/home/doctor/Desktop/cognitusFiles/csv/$TABLENAME.csv
        done
}

function initialStart() {

    find . -path "*/migrations/*.py" -not -name "__init__.py" -delete
    find . -path "*/migrations/*.pyc" -delete
    pip install --upgrade --force-reinstall Django==1.11.1projects
    python manage.py migrate --fake-initial
}



function clear() {

    kill -9 $(lsof -t -i:8000) || echo "ok" &&
        kill -9 $(lsof -t -i:8000) || echo "ok" &&
        kill -9 $(lsof -t -i:5000) || echo "ok" &&
        docker container stop $(docker container ls -aq) || echo "ok" &&
        docker container rm $(docker container ls -aq) || echo "ok" &&
        docker volume prune || echo "ok" &&
        docker network prune || echo "ok" &&
        docker image prune || echo "ok" &&
        docker image prune -a || echo "ok" &&
        docker service rm $(docker service ls) || echo "ok" &&
        docker-machine rm -f $(docker-machine ls) || echo "ok" &&
         ps -ef| grep -i My-Locked-VM
        VBoxManage list vms

}

function clear2() {
    kill -9 $(lsof -t -i:5060) || echo "ok" &&
        docker-compose down -v || echo "" &&
        docker container kill $(docker container ls -aq) || echo "ok" &&
        docker container stop $(docker container ls -aq) || echo "ok" &&
        docker container rm $(docker container ls -aq) || echo "ok" &&
        docker system prune --volumes || echo "ok" &&
        docker volume prune || echo "ok" &&
        docker volume rm $(docker volume ls -q) &&
        docker network prune || echo "ok"

}

function go() {

    kill -9 $(lsof -t -i:8000) || echo "ok" &&
        python manage.py runserver
}

function init() {
    docker-compose -f docker-compose.yml down -v &&
        docker-compose -f source/airflow/docker-compose-LocalExecutor.yml down -v &&
        docker-compose -f docker-compose.yml up -d --build &&
        docker-compose -f docker-compose.yml exec web python manage.py migrate --noinput &&
        docker-compose -f docker-compose.yml exec web python manage.py collectstatic --no-input &&
        docker-compose up -d --no-deps --build web &&
        docker-compose -f source/airflow/docker-compose-LocalExecutor.yml up -d --build
}

function init_justup() {

    docker-compose -f docker-compose.yml up -d --build &&
        docker-compose -f docker-compose.yml exec web python manage.py migrate --noinput &&
        docker-compose -f docker-compose.yml exec web python manage.py collectstatic --no-input &&
        docker-compose up -d --no-deps --build web &&
        docker-compose -f source/airflow/docker-compose-LocalExecutor.yml up -d --build
}

function mysql() {
    apt-get install mysql-server &&
        apt-get install mysql-server libapache2-mod-auth-mysql &&
        service mysql start &&
        mysql -u root -p &&
        create database test
    show databases
    quit

}
# Check if the function exists (bash specific)
if declare -f "$1" >/dev/null; then
    # call arguments verbatim
    "$@"
else
    # Show a helpful error
    echo "'$1' is not a known function name" >&2
    exit 1
fi

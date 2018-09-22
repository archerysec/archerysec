#!/bin/bash
set -ex

# Docker Build
export $CONTAINER_NAME=archery
docker build -t $REPO .
docker run -d -p 127.0.0.1:8000:8000 --name=$CONTAINER_NAME $REPO
docker logs $CONTAINER_NAME
pip install bandit
docker ps -a
docker logs $CONTAINER_NAME
echo "Checking to see if dojo is running"

# Check whether the container is running and came up as expected
set +e
STATE="inactive"
for i in $(seq 1 5); do
    curl -s -o /dev/null http://127.0.0.1:8000/login?next=/
    if [ "$?" == "0" ]; then
        STATE="running"
        break
    fi
    sleep 10
done
if [ "$STATE" != "running" ]; then
    docker ps -a
    docker logs $CONTAINER_NAME
    echo "Container did not come up properly" >&2
    exit 1
fi
set -e

export DISPLAY=:99.0
sh -e /etc/init.d/xvfb start
sleep 3 # give xvfb some time to start
whereis chromedriver
export PATH=$PATH:/usr/local/bin/
python tests/check_status.py -v
python tests/smoke_test.py
# python tests/zap.py

set +ex

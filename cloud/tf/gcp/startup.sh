#!/bin/bash

sudo useradd -m -s /bin/bash -G sudo nebula

# install docker
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update

sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# add the nebula user to the right group for docker
sudo usermod -aG docker nebula

# set environment variables
export SERVER_PORT=${server_port}
echo "export SERVER_PORT=${server_port}" >> /home/nebula/.bashrc

export SERVER_MODE=${server_mode}
echo "export SERVER_MODE=${server_mode}" >> /home/nebula/.bashrc

export PROVIDER_URL=${provider_url}
echo "export PROVIDER_URL=${provider_url}" >> /home/nebula/.bashrc

terraform {
  required_providers {
    docker = {
      source = "kreuzwerker/docker"
      version = "~> 3.0.2"
    }
  }
}

variable "provider_port" {
  type = number 
  default = 8000
}

variable "appserver_port" {
  type = number 
  default = 8080
}

provider "docker" {}

resource "docker_image" "galaxy_cloud" {
  name         = "galaxy_cloud:latest"
  keep_locally = true 
}

resource "docker_network" "galaxy_net" {
  name = "galaxy_net"
}

resource "docker_container" "galaxy_provider" {
  image = docker_image.galaxy_cloud.image_id
  name  = "provider"
  rm    = true
  tty   = true
  env   = [
    "SERVER_PORT=${var.provider_port}",
    "SERVER_MODE=provider",
    "SERVER_TLS=false",
    "APPSERVER_URL=http://appserver:${var.appserver_port}"
  ]
  networks_advanced {
    name = docker_network.galaxy_net.name
    aliases = ["provider"]
  }
  ports {
    internal = var.provider_port
    external = var.provider_port
  }
}

resource "docker_container" "galaxy_appserver" {
  image = docker_image.galaxy_cloud.image_id
  name  = "appserver"
  rm    = true
  tty   = true
  env   = [
    "SERVER_PORT=${var.appserver_port}",
    "SERVER_MODE=app",
    "SERVER_TLS=false",
    "PROVIDER_URL=http://provider:${var.provider_port}"
  ]
  networks_advanced {
    name = docker_network.galaxy_net.name
    aliases = ["appserver"]
  }
  ports {
    internal = var.appserver_port
    external = var.appserver_port
  }
}

terraform {
  required_providers {
    docker = {
      source = "kreuzwerker/docker"
      version = "~> 3.0.2"
    }
    google = {
      source = "hashicorp/google"
      version = "~> 4.61.0"
    }
    random = {
      source = "hashicorp/random"
      version = "~> 3.5.0"
    }
    acme = {
      source = "vancluever/acme"
      version = "~> 2.0"
    }
    aws = {
      source = "hashicorp/aws"
      version = "~> 4.67.0"
    }
  }
}

// --- Setup GCP provider ---

variable "default_region" {
  type = string
  default = "us-central1"
}

variable "default_zone" {
  type = string
  default = "us-central1-a"
}

variable "client_email" {
  type = string
}

provider "google" {
  project     = "opportunistic-networks-galaxy"
  region      = var.default_region
}

provider "aws" {
  shared_credentials_files = [pathexpand("~/.aws/credentials")]
  profile = "default"
  region = "us-east-1"
}

// --- Store terraform state in GCP storage bucket ---

resource "random_id" "bucket_prefix" {
  byte_length = 8
}

resource "google_storage_bucket" "tfstate" {
  name          = "${random_id.bucket_prefix.hex}-bucket-tfstate"
  location      = var.default_region
  force_destroy = false
  storage_class = "STANDARD"
}

// --- Setup ACME (e.g. Let's Encrypt) ---

provider "acme" {
  server_url = "https://acme-v02.api.letsencrypt.org/directory"
}

resource "tls_private_key" "reg_private_key" {
  algorithm = "RSA"
}

resource "acme_registration" "reg" {
  account_key_pem = tls_private_key.reg_private_key.private_key_pem
  email_address   = "lab11@berkeley.edu"
}

resource "tls_private_key" "provider_private_key" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "provider_req" {
  private_key_pem = tls_private_key.provider_private_key.private_key_pem
  dns_names       = ["provider.nebula.lab11.org"]

  subject {
    common_name = "provider.nebula.lab11.org"
  }
}

resource "acme_certificate" "provider_cert" {
  account_key_pem         = acme_registration.reg.account_key_pem
  certificate_request_pem = tls_cert_request.provider_req.cert_request_pem

  // assumes lab11 credentials are being used
  dns_challenge {
    provider = "route53"
  }
}

resource "tls_private_key" "appserver_private_key" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_cert_request" "appserver_req" {
  private_key_pem = tls_private_key.appserver_private_key.private_key_pem
  dns_names       = ["app.nebula.lab11.org"]

  subject {
    common_name = "app.nebula.lab11.org"
  }
}

resource "acme_certificate" "appserver_cert" {
  account_key_pem         = acme_registration.reg.account_key_pem
  certificate_request_pem = tls_cert_request.appserver_req.cert_request_pem

  // assumes lab11 credentials are being used
  dns_challenge {
    provider = "route53"
  }
}

// --- Set up SSH, HTTP, and HTTPS firewall rules ---

resource "google_compute_firewall" "allow_ssh" {
  name    = "allow-ssh"
  network = "default-galaxy-network"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]

  target_tags = ["allow-ssh"]
}

resource "google_compute_firewall" "allow_http" {
  name    = "allow-http"
  network = "default-galaxy-network"

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  source_ranges = ["0.0.0.0/0"]

  target_tags = ["allow-http"]
}

resource "google_compute_firewall" "allow_https" {
  name    = "allow-https"
  network = "default-galaxy-network"

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["0.0.0.0/0"]

  target_tags = ["allow-https"]
}

// --- Provision docker image on provider and app server machines ---
provider "docker" {
  registry_auth {
    address = "gcr.io"
    username = "_json_key"
    password = "${file(pathexpand("~/.creds/opportunistic-networks-galaxy-206a92151ad6.json"))}"
  }
}

data "google_compute_image" "cos" {
  family  = "cos-stable"
  project = "cos-cloud"
}

data "docker_registry_image" "galaxy_cloud" {
  name = "gcr.io/opportunistic-networks-galaxy/galaxy_cloud"
}

resource "docker_image" "galaxy_cloud" {
  name = data.docker_registry_image.galaxy_cloud.name
  pull_triggers = [data.docker_registry_image.galaxy_cloud.sha256_digest]
}

resource "google_compute_instance" "lab11_provider" {
  name        = "lab11-provider"
  machine_type = "e2-medium"
  zone        = var.default_zone
  allow_stopping_for_update = true

  tags = ["allow-ssh", "allow-https"]

  boot_disk {
    initialize_params {
      image = data.google_compute_image.cos.self_link
      size = 100
    }
  }

  network_interface {
     network = "default-galaxy-network"
     access_config {
     }
  }

  metadata = {
    gce-container-declaration = "spec:\n  containers:\n  - name: provider\n    image: ${docker_image.galaxy_cloud.name}\n    env:\n    - name: SERVER_MODE\n      value: provider\n    - name: SERVER_PORT\n      value: '443'\n    - name: PROVIDER_URL\n      value: provider.nebula.lab11.org\n    volumeMounts:\n    - name: certs\n      readOnly: true\n      mountPath: /certs\n    stdin: false\n    tty: false\n  volumes:\n  - name: certs\n    hostPath:\n      path: /tmp/certs\n  restartPolicy: Always\n"
  }
  metadata_startup_script = <<-EOF
    echo "${docker_image.galaxy_cloud.repo_digest}" > /tmp/docker_image_name.txt
    mkdir -p /tmp/certs
    echo "${acme_certificate.provider_cert.certificate_pem}${acme_certificate.provider_cert.issuer_pem}" > /tmp/certs/cert.pem
    echo "${tls_private_key.provider_private_key.private_key_pem}" > /tmp/certs/key.pem
  EOF

  service_account {
    email = "1064507374211-compute@developer.gserviceaccount.com"
    scopes = [
      "https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/trace.append"
    ]
  }
}

resource "google_compute_instance" "lab11_app_server" {
  name        = "lab11-app-server"
  machine_type = "e2-medium"
  zone        = var.default_zone
  allow_stopping_for_update = true

  tags = ["allow-ssh", "allow-https"]

  boot_disk {
    initialize_params {
      image = data.google_compute_image.cos.self_link
      size = 100
    }
  }

  network_interface {
     network = "default-galaxy-network"
     access_config {
     }
  }

  metadata = {
    gce-container-declaration = "spec:\n  containers:\n  - name: appserver\n    image: ${docker_image.galaxy_cloud.name}\n    env:\n    - name: SERVER_MODE\n      value: app\n    - name: SERVER_PORT\n      value: '443'\n    - name: PROVIDER_URL\n      value: provider.nebula.lab11.org\n    volumeMounts:\n    - name: certs\n      readOnly: true\n      mountPath: /certs\n    stdin: false\n    tty: false\n  volumes:\n  - name: certs\n    hostPath:\n      path: /tmp/certs\n  restartPolicy: Always\n"
  }
  metadata_startup_script = <<-EOF
    echo "${docker_image.galaxy_cloud.repo_digest}" > /tmp/docker_image_name.txt
    mkdir -p /tmp/certs
    echo "${acme_certificate.appserver_cert.certificate_pem}${acme_certificate.appserver_cert.issuer_pem}" > /tmp/certs/cert.pem
    echo "${tls_private_key.appserver_private_key.private_key_pem}" > /tmp/certs/key.pem
  EOF

  service_account {
    email = "1064507374211-compute@developer.gserviceaccount.com"
    scopes = [
      "https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/trace.append"
    ]
  }
}

// --- Set up DNS records ---

variable "lab11_zone_id" {
  type = string
  default = "Z01723792SFGQ2BMKSLRW"
}

resource "aws_route53_record" "provider_record" {
  zone_id = var.lab11_zone_id
  name    = "provider.nebula.lab11.org"
  type    = "A"
  ttl     = "300"
  records = [google_compute_instance.lab11_provider.network_interface.0.access_config.0.nat_ip]
}

resource "aws_route53_record" "appserver_record" {
  zone_id = var.lab11_zone_id
  name    = "app.nebula.lab11.org"
  type    = "A"
  ttl     = "300"
  records = [google_compute_instance.lab11_app_server.network_interface.0.access_config.0.nat_ip]
}

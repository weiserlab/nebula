SERVER_PORT ?= 80
PROVIDER_PORT ?= 443
SERVER_MODE ?= app
PROVIDER_URL ?=http://0.0.0.0:443

.PHONY: build local remote clean destroy-local destroy-remote keypair

local: build
	cd tf/local && terraform init && terraform apply -auto-approve

docker: build
	docker tag galaxy_cloud gcr.io/opportunistic-networks-galaxy/galaxy_cloud:latest
	docker push gcr.io/opportunistic-networks-galaxy/galaxy_cloud:latest

remote: build
	docker tag galaxy_cloud gcr.io/opportunistic-networks-galaxy/galaxy_cloud:latest
	docker push gcr.io/opportunistic-networks-galaxy/galaxy_cloud:latest

	cd tf/gcp && terraform init && terraform apply -auto-approve

provider-local: build
	sudo docker run -it --rm -p 443:443 --name provider --env SERVER_PORT=$(PROVIDER_PORT) --env SERVER_MODE=provider galaxy_cloud

appserver-local: build
	sudo docker run -it --rm --name app-server --env SERVER_PORT=$(SERVER_PORT) --env SERVER_MODE=app --env PROVIDER_URL=$(PROVIDER_URL) -p 80:80 galaxy_cloud

build:
	mkdir -p _build
	cp -r ../ext/anonymous-tokens _build/
	docker build -t galaxy_cloud .

clean: 
	rm -rf _build

destroy-local:
	cd tf/local && terraform destroy -auto-approve

destroy-remote:
	cd tf/gcp && terraform destroy -auto-approve

keypair:
	maturin develop --manifest-path anonymous-tokens-lib/Cargo.toml --release
	python gen_keypair.py
	python gen_credentials.py

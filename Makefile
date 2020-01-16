MAKEFLAGS += --silent
.PHONY: deploy run build clean kill log help

deploy: | build clean
	docker-compose up -d

run: | build clean
	docker-compose up

clean: kill
	docker-compose rm -f

build:
	docker-compose build

kill:
	docker-compose down --remove-orphans

log:
	docker-compose logs -f

help:
	echo "HELP"
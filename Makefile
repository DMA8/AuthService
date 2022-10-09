all: docker.start test.integration docker.stop

docker.start:
	docker-compose -f internal/tests/docker-compose.yaml up -d
	sleep 5

docker.stop:
	docker-compose -f internal/tests/docker-compose.yaml kill

docker.restart: docker.stop docker.start

test.unit:
	go test ./... -cover

test.integration:
	go test -tags=integration ./internal/tests -v -count=1

gen:
	mockgen -source=internal/ports/auth_storage.go \
	-destination=internal/mocks/mock_auth_storage.go
	mockgen -source=internal/ports/auth.go \
	-destination=internal/mocks/mock_auth.go
	mockgen -source=internal/ports/grpc.go \
	-destination=internal/mocks/mock_grpc.go

swag:
	swag init -g internal/api/api.go
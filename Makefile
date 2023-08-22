default:

benchmark:
	go test -bench=. ./...

lint:
	golangci-lint run ./...

test:
	go test -cover -v ./...

# -- Vulnerability scanning --

trivy:
	trivy fs . \
		--dependency-tree \
		--exit-code 1 \
		--format table \
		--ignore-unfixed \
		--quiet \
		--scanners config,license,secret,vuln \
		--severity HIGH,CRITICAL \
		--skip-dirs docs

.PHONY: build build.agentiod build.epe clean fmt format gen gen.crddocs lint lint.logging racetest test test.epe test.integration.agentio.kube test.integration.agentio.product tidy

build: build.agentiod build.epe

build.agentiod:
	mkdir -p out
	go build -trimpath -o out/agentiod ./cmd/agentiod

build.epe:
	mkdir -p out
	go build -trimpath -o out/epe ./extensions/epe/cmd/epe

test.epe:
	go test ./extensions/epe/...

test:
	go test ./...
	go -C test/e2e test ./...

test.integration.agentio.kube:
	@for tool in docker kind kubectl helm; do \
		command -v $$tool >/dev/null || { echo "required integration test tool '$$tool' is unavailable" >&2; exit 1; }; \
	done
	E2E_FRAMEWORK_SMOKE=1 go -C test/e2e test ./suites/framework -run '^TestFrameworkSmoke$$' -v -count=1

AGENTIO_E2E_SUITES ?= ./suites/...

test.integration.agentio.product:
	@for tool in docker kind kubectl helm; do \
		command -v $$tool >/dev/null || { echo "required integration test tool '$$tool' is unavailable" >&2; exit 1; }; \
	done
	AGENTIO_E2E=1 go -C test/e2e test -p 1 $(AGENTIO_E2E_SUITES) -v -count=1

# The control plane runs a goroutine per collection, per handler registration and
# per xDS stream, so the race detector is part of the normal gate rather than an
# occasional extra.
racetest:
	go test -race -count=1 ./...
	go -C test/e2e test -race -count=1 ./...

lint:
	go vet ./...
	go -C test/e2e vet ./...

# The logging convention check diffs against a merge base, which the shallow
# checkout in agentio-ut.yml cannot supply, so it runs in its own workflow
# instead of here. Called without an argument it resolves the base itself.
lint.logging:
	./bin/lint_logging.sh

gen:
	./tools/generate-proto.sh
	./tools/generate-crd-docs.sh

gen.crddocs:
	./tools/generate-crd-docs.sh

format: fmt

fmt:
	go fmt ./...
	go -C test/e2e fmt ./...

tidy:
	go mod tidy
	go -C test/e2e mod tidy

clean:
	rm -rf out

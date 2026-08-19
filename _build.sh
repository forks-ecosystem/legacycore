cd /home/coin/LegacyCore
go version
go test ./...
go vet ./...
CGO_ENABLED=0 go build -o legacycoind ./cmd/legacycoind
CGO_ENABLED=0 go build -o legacycoin-cli ./cmd/legacycoin-cli
ls -lah ./legacycoind ./legacycoin-cli
./legacycoind params

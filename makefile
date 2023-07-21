build:
	ksc -t go --go-package parsers windows_minidump.ksy
	go build -o warbler -ldflags="-s -w" -trimpath warbler.go
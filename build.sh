#!/bin/sh

path=$(realpath "$(dirname "$0")") || exit 1
rm -rf "$path/../../services/burgernotes.fgs" || exit 1
cd "$path" || exit 1
protoc -I="$path" --go_out="$path" "$path/protobufs/main.proto" || exit 1
go build -o "$path/../../services/burgernotes.fgs" --buildmode=plugin -ldflags "-s -w" || exit 1

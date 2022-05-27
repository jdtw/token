.PHONY: proto

proto/token/token.pb.go: proto/token/token.proto
	protoc --go_out=. --go_opt=paths=source_relative proto/token/token.proto

proto: proto/token/token.pb.go
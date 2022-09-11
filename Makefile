.PHONY: all
all:
	go build -buildmode=plugin -o plugins ./plugins/portscanner/
	go build -buildmode=plugin -o plugins ./plugins/databasescanner/
	go run main.go --config=.pengo.yaml

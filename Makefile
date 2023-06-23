.PHONY: all clean

#all: cmetry-cli cmetry-server

build: run

cmetry-cli:
	mkdir -p bins/
	go build -trimpath -o bins/cmetry-cli ./cmds/cmetry-cli

cmetry-server:
	mkdir -p bins/
	go build -trimpath -o bins/cmetry-server ./cmds/cmetry-server

run:
	go run cmds/cmetry-server/main.go $(MAKECMDGOALS) 

clean:
	rm -rf bins/

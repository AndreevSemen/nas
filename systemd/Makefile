all: compile setup-service

compile:
	go build -o /usr/bin/nas-server ../cmd/nas-server/main.go

setup-service:
	cp nas-server.service /lib/systemd/system/
	cp ../workplace/config.yaml /etc/nas-server/
	systemctl daemon-reload

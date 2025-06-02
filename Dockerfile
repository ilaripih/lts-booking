FROM golang:1.24

CMD cd /app && GOFLAGS=-buildvcs=false go build -o lts-booking

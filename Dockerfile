FROM golang:1.16

RUN \
  go get github.com/gorilla/context && \
  go get github.com/gorilla/sessions && \
  go get gopkg.in/mgo.v2 && \
  go get gopkg.in/mgo.v2/bson && \
  go get golang.org/x/crypto/bcrypt && \
  go get golang.org/x/crypto/acme/autocert

CMD cd /app && go build -o lts-booking

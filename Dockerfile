FROM ubuntu:20.04

RUN apt-get update && apt-get install apt-utils ca-certificates locales software-properties-common -y \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
    wget && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN cd /tmp && \
    wget https://golang.org/dl/go1.24.3.linux-amd64.tar.gz && \
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.24.3.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin GOPATH=/go

CMD cd /app && go build -o lts-booking

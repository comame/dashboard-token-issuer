FROM golang:1.20 AS builder

WORKDIR /usr/src/app

COPY . .
RUN go build -v -o ./dist


FROM ubuntu

COPY --from=builder /usr/src/app/dist /usr/local/bin/dist
CMD /usr/local/bin/dist

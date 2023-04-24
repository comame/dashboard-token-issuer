FROM golang AS builder

WORKDIR /usr/src/app

COPY . .
RUN go build -v -o ./dist


FROM alpine

RUN apk add --no-cache libc6-compat
COPY --from=builder /usr/src/app/dist /usr/local/bin/dist
RUN ls /usr/local/bin
CMD /usr/local/bin/dist

FROM golang:alpine as builder
RUN apk add --update git
RUN mkdir /build
ADD . /build/
WORKDIR /build/cmd
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o main .

FROM scratch
COPY --from=builder /build/cmd/main /app/
WORKDIR /app
EXPOSE 8080
CMD ["./main"]
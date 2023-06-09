FROM golang as builder
RUN mkdir  /build
WORKDIR /build
COPY *go *.mod /build
RUN go mod tidy && CGO_ENABLED=0 go build 
FROM alpine
EXPOSE 8443/tcp
RUN mkdir /app
WORKDIR /app
COPY --from=builder /build/tlsecho /app
CMD ["./tlsecho"]

FROM alpine:latest
RUN apk add --no-cache ca-certificates tzdata
COPY mint-ca /usr/local/bin/mint-ca
EXPOSE 8443
VOLUME ["/data"]
ENTRYPOINT ["mint-ca"]
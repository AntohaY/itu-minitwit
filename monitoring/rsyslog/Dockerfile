FROM ubuntu:24.04

# hadolint ignore=DL3008 
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends rsyslog ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/lib/rsyslog /var/log/remote

COPY rsyslog.conf /etc/rsyslog.conf
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 514/tcp 514/udp

CMD ["/entrypoint.sh"]

FROM grafana/grafana:12.1

ENV PROMETHEUS_HOST='host.docker.internal:9090'

COPY dashboards /etc/grafana/provisioning/dashboards
COPY datasources /etc/grafana/provisioning/datasources

EXPOSE 3000

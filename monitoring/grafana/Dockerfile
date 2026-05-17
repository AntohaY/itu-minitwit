FROM grafana/grafana:12.1

COPY dashboards /etc/grafana/provisioning/dashboards
COPY datasources /etc/grafana/provisioning/datasources
COPY alerting /etc/grafana/provisioning/alerting

EXPOSE 3000

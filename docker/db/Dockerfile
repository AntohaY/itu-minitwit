FROM mongo:8.0

# 1. You MUST copy the actual data so the script has something to restore!
COPY ./dump/ /tmp/dump/mydb/

# 2. Copy the initialization script
COPY ./docker/db/import_data.sh /docker-entrypoint-initdb.d/import_data.sh

# 3. Make sure the script is executable
RUN chmod +x /docker-entrypoint-initdb.d/import_data.sh
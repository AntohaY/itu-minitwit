FROM mongo:8.0

# Copy your initialization script to the special initdb directory
COPY ./docker/db/import_data.sh /docker-entrypoint-initdb.d/import_data.sh

# Make sure the script is executable
RUN chmod +x /docker-entrypoint-initdb.d/import_data.sh

# CMD chmod 777 /docker-entrypoint-initdb.d/import_data.sh
#CMD mongod --fork --logpath /var/log/mongodb.log; \
#    mongorestore --gzip /tmp/dump/mydb/; \
#    mongod --shutdown; \
#    docker-entrypoint.sh mongod
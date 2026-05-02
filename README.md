# Project readme <br>

## Git and branches <br> 
Naming convention:
{fix/feature}/week-{assignment_number_of_week}/{short_message}

## CI/CD
### Project infrastructure is setup with Vagrant. Run _vagrant up_ to create virtual machines (droplets) on Digital Ocean.
### Everytime a merge is done into the _main_ branch GithubActions perform continuous deployment to update the project with latest changes. 

## How to run env locally
### 1. Create an .env file in root folder and setup environment variables
    DOCKER_USERNAME=****
    GRAFANA_ADMIN_USER=****
    GRAFANA_ADMIN_PASSWORD=****
### 2. Run this command to start docker
    docker compose up --build

#### 2.1 Update commands for routing, nginx, etc.
    vagrant rsync
    export TLS_DOMAIN=your-domain.com
    export TLS_EMAIL=you@example.com
    ./setup-swarm.sh

### 3. API test
To test API you can use _test-api-routes.sh_ script.
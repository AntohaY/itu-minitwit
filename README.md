# Project readme <br>

## Git and branches <br> 
Naming convention:
{fix/feature}//{short_message}

## CI/CD
### Project infrastructure is setup with Vagrant. Run _vagrant up_ to create virtual machines (droplets) on Digital Ocean.
### Everytime a merge is done into the _main_ branch GithubActions perform continuous deployment to update the project with latest changes. 

## How to run env locally
### 1. Prepare local prerequisites for `vagrant up`
    export DIGITAL_OCEAN_TOKEN=****

Create an SSH key pair locally at:
    ~/.ssh/ssh_key_golang_minitwit

Add the matching public key to DigitalOcean with this exact key name:
    ssh_key_golang_minitwit

Optional if you want TLS/Nginx bootstrap during the same run:
    export TLS_DOMAIN=your-domain.com
    export TLS_EMAIL=you@example.com

### 2. Create an `.env` file in root folder and setup deployment environment variables
    DOCKER_USERNAME=****
    DISCORD_TOKEN=****
    GRAFANA_ADMIN_USER=****
    GRAFANA_ADMIN_PASSWORD=****
    MONGO_URI=****

`vagrant up` creates the droplets and then automatically runs `setup-swarm.sh`, so these variables must be available locally when you run it.

### 3. Run this command to create infrastructure and deploy the Swarm stack
    vagrant up

### 4. Run this command to start docker locally
    docker compose up --build

#### 4.1 Re-run deployment, routing, or TLS setup on existing droplets
    vagrant rsync
    export TLS_DOMAIN=your-domain.com
    export TLS_EMAIL=you@example.com
    ./setup-swarm.sh

`setup-swarm.sh` loads deployment variables from the local `.env` file or the current shell environment and passes them directly to the manager node. The `.env` file is no longer synced through `Vagrantfile`.

### 5. API test
To test API you can use _test-api-routes.sh_ script.

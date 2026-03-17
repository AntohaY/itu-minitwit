import dagger
from dagger import dag, function, object_type
# Powershell command to setup the env
# $env:SSH_USER="root"
# $env:SSH_HOST="your_droplet_ip"
# $env:DOCKER_USERNAME="your_docker_username"
# $env:DISCORD_TOKEN="your_discord_token"
# $env:GRAFANA_ADMIN_USER="admin"
# $env:GRAFANA_ADMIN_PASSWORD="grafana_password"

# dagger call lint --source .
# dagger call publish-images --source . --docker-username $env:DOCKER_USERNAME --docker-password env:DOCKER_PASSWORD
# dagger call deploy `
#     --source . `
#     --ssh-user $env:SSH_USER `
#     --ssh-host $env:SSH_HOST `
#     --docker-username $env:DOCKER_USERNAME `
#     --discord-token env:DISCORD_TOKEN `
#     --grafana-admin-user env:GRAFANA_ADMIN_USER `
#     --grafana-admin-password env:GRAFANA_ADMIN_PASSWORD `
#     --ssh-key file:C:\Users\YourName\.ssh\ssh_key_golang_minitwit
@object_type
class ItuMinitwit:
    @function
        async def lint(self, source: dagger.Directory) -> str:
            """Runs the golangci-lint checker against the source code."""

            linter = (
                dag.container()
                .from_("golangci/golangci-lint:latest")
                .with_directory("/src", source)
                .with_workdir("/src")
                .with_exec(["golangci-lint", "run", "./..."])
            )

            output = await linter.stdout()
            return f"Linting passed successfully!\n{output}"

    @function
    async def publish_images(
        self,
        source: dagger.Directory,
        docker_username: str,
        docker_password: dagger.Secret
    ) -> str:
        """Builds and publishes the DB, Web, and Bot images to Docker Hub."""

        # 1. Build the images (same as before)
        db_image = source.docker_build(dockerfile="./docker/db/Dockerfile")
        web_image = source.docker_build(dockerfile="./docker/web/Dockerfile")
        bot_image = source.directory("./new/bot").docker_build(dockerfile="Dockerfile")

        # 2. Define the image tags
        db_tag = f"docker.io/{docker_username}/dbminitwitimage:latest"
        web_tag = f"docker.io/{docker_username}/webminitwitimage:latest"
        bot_tag = f"docker.io/{docker_username}/discordbotimage:latest"

        # 3. Authenticate and Publish!
        # We chain .with_registry_auth() onto our built containers before calling .publish()
        db_pushed = await (
            db_image
            .with_registry_auth("docker.io", docker_username, docker_password)
            .publish(db_tag)
        )

        web_pushed = await (
            web_image
            .with_registry_auth("docker.io", docker_username, docker_password)
            .publish(web_tag)
        )

        bot_pushed = await (
            bot_image
            .with_registry_auth("docker.io", docker_username, docker_password)
            .publish(bot_tag)
        )

        return f"Successfully published!\nDB: {db_pushed}\nWeb: {web_pushed}\nBot: {bot_pushed}"

    @function
        async def deploy(
            self,
            source: dagger.Directory,
            ssh_user: str,
            ssh_host: str,
            ssh_key: dagger.Secret,
            docker_username: str,
            discord_token: dagger.Secret,
            grafana_admin_user: dagger.Secret,
            grafana_admin_password: dagger.Secret
        ) -> str:
            """Deploys the application to the DigitalOcean droplet via SSH."""

            # Spin up a temporary Alpine container with SSH installed
            deploy_container = (
                dag.container()
                .from_("alpine:latest")
                .with_exec(["apk", "add", "--no-cache", "openssh-client"])

                # Mount the SSH key securely so it isn't saved in the container's history
                .with_mounted_secret("/root/.ssh/id_rsa", ssh_key)
                .with_exec(["chmod", "600", "/root/.ssh/id_rsa"])

                # Bring your source code into this temporary container
                .with_directory("/src", source)
                .with_workdir("/src")

                # Pass our secrets as environment variables securely
                .with_env_variable("DOCKER_USERNAME", docker_username)
                .with_secret_variable("DISCORD_TOKEN", discord_token)
                .with_secret_variable("GRAFANA_ADMIN_USER", grafana_admin_user)
                .with_secret_variable("GRAFANA_ADMIN_PASSWORD", grafana_admin_password)

                # 1. Create the .env file inside the container
                .with_exec([
                    "sh", "-c",
                    "echo DOCKER_USERNAME=$DOCKER_USERNAME >> .env && "
                    "echo DISCORD_TOKEN=$DISCORD_TOKEN >> .env && "
                    "echo GRAFANA_ADMIN_USER=$GRAFANA_ADMIN_USER >> .env && "
                    "echo GRAFANA_ADMIN_PASSWORD=$GRAFANA_ADMIN_PASSWORD >> .env"
                ])

                # 2. SCP the files (Notice we included -r and the monitoring folder!)
                .with_exec([
                    "sh", "-c",
                    f"scp -i /root/.ssh/id_rsa -o StrictHostKeyChecking=no -r remote_files/docker-compose.yml remote_files/deploy.sh remote_files/prometheus.yml .env monitoring {ssh_user}@{ssh_host}:/minitwit/"
                ])

                # 3. SSH into the server and run the deploy script
                .with_exec([
                    "ssh", "-i", "/root/.ssh/id_rsa", "-o", "StrictHostKeyChecking=no",
                    f"{ssh_user}@{ssh_host}",
                    "chmod +x /minitwit/deploy.sh && cd /minitwit && ./deploy.sh"
                ])
            )

            # Execute the container and grab the terminal output
            output = await deploy_container.stdout()
            return f"Deployment successful!\nLogs:\n{output}"
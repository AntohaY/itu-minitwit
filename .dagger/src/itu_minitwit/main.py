import dagger
from dagger import dag, function, object_type

@object_type
class ItuMinitwit:
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
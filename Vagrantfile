# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = 'digital_ocean'
  config.vm.box_url = "https://github.com/devopsgroup-io/vagrant-digitalocean/raw/master/box/digital_ocean.box"
  config.ssh.private_key_path = '~/.ssh/ssh_key_golang_minitwit'

  NEW_DROPLETS = [
    "minitwit",
    "minitwit-web-1",
    "minitwit-web-2"
  ]

  NEW_DROPLETS.each do |droplet|
    config.vm.define droplet do |server|
      server.vm.provider :digital_ocean do |provider|
        provider.ssh_key_name = "ssh_key_golang_minitwit"
        provider.token = ENV["DIGITAL_OCEAN_TOKEN"]
        provider.image = 'ubuntu-22-04-x64'
        provider.region = 'fra1'
        provider.size = 's-1vcpu-1gb'
      end

      server.vm.synced_folder "remote_files", "/#{droplet}", type: "rsync"
      server.vm.synced_folder '.', '/vagrant', disabled: true

      server.vm.hostname = droplet

      server.vm.provision "shell", inline: "echo 'export DOCKER_USERNAME=\"#{ENV["DOCKER_USERNAME"]}\"' >> ~/.bash_profile"
      server.vm.provision "shell", inline: "echo 'export DOCKER_PASSWORD=\"#{ENV["DOCKER_PASSWORD"]}\"' >> ~/.bash_profile"

      server.vm.provision "shell", inline: <<-SHELL
        # Prevent interactive prompts from stalling the installation
        export DEBIAN_FRONTEND=noninteractive

        echo -e "\\nWaiting for DigitalOcean background updates (cloud-init) to finish completely..."
        cloud-init status --wait

        echo -e "\\nUpdating package list..."
        sudo apt-get update

        echo -e "\\nInstalling docker and docker compose via official script..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh

        sudo systemctl status docker

        echo -e "\\nVerifying that docker works ...\\n"
        docker run --rm hello-world
        docker rmi hello-world

        echo -e "\nOpening ports for application and Docker Swarm...\n"
        ufw allow 5000/tcp
        ufw allow 22/tcp

        # Docker Swarm Ports
        ufw allow 2377/tcp   # Cluster management communications
        ufw allow 7946/tcp   # Communication among nodes
        ufw allow 7946/udp   # Communication among nodes
        ufw allow 4789/udp   # Overlay network traffic

        # Reload ufw to apply
        ufw reload

        echo ". $HOME/.bashrc" >> $HOME/.bash_profile

        echo -e "\\nConfiguring credentials as environment variables...\\n"
        source $HOME/.bash_profile

        echo -e "\\nSelecting #{droplet} Folder as default folder when you ssh into the server...\\n"
        echo "cd /#{droplet}" >> ~/.bash_profile

        sudo usermod -aG docker $USER

      SHELL
    end
  end
end
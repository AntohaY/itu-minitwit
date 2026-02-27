# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = 'digital_ocean'
  config.vm.box_url = "https://github.com/devopsgroup-io/vagrant-digitalocean/raw/master/box/digital_ocean.box"
  config.ssh.private_key_path = '~/.ssh/ssh_key_golang_minitwit'

  config.vm.synced_folder "remote_files", "/minitwit", type: "rsync"
  config.vm.synced_folder '.', '/vagrant', disabled: true

  config.vm.define "minitwit", primary: true do |server|

    server.vm.provider :digital_ocean do |provider|
      provider.ssh_key_name = "ssh_key_golang_minitwit"
      provider.token = ENV["DIGITAL_OCEAN_TOKEN"]
      provider.image = 'ubuntu-22-04-x64'
      provider.region = 'fra1'
      provider.size = 's-1vcpu-1gb'
    end

    server.vm.hostname = "minitwit-p"

    server.vm.provision "shell", inline: 'echo "export DOCKER_USERNAME=' + "'" + ENV["DOCKER_USERNAME"] + "'" + '" >> ~/.bash_profile'
    server.vm.provision "shell", inline: 'echo "export DOCKER_PASSWORD=' + "'" + ENV["DOCKER_PASSWORD"] + "'" + '" >> ~/.bash_profile'

    server.vm.provision "shell", inline: <<-SHELL

    # Prevent interactive prompts from stalling the installation
    export DEBIAN_FRONTEND=noninteractive

    echo -e "\nWaiting for DigitalOcean background updates (cloud-init) to finish completely..."
    cloud-init status --wait

    echo -e "\nUpdating package list..."
    sudo apt-get update

    echo -e "\nInstalling docker and docker compose via official script..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh

    sudo systemctl status docker
    # sudo usermod -aG docker ${USER}

    echo -e "\nVerifying that docker works ...\n"
    docker run --rm hello-world
    docker rmi hello-world

    echo -e "\nOpening port for minitwit ...\n"
    ufw allow 5000 && \
    ufw allow 22/tcp

    echo ". $HOME/.bashrc" >> $HOME/.bash_profile

    echo -e "\nConfiguring credentials as environment variables...\n"

    source $HOME/.bash_profile

    echo -e "\nSelecting Minitwit Folder as default folder when you ssh into the server...\n"
    echo "cd /minitwit" >> ~/.bash_profile

    chmod +x /minitwit/deploy.sh

    echo -e "\nVagrant setup done ..."
    echo -e "minitwit will later be accessible at http://$(hostname -I | awk '{print $1}'):5000"
    echo -e "The mysql database needs a minute to initialize, if the landing page shows an error stack-trace ..."

    SHELL
  end
end
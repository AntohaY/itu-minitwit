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

    sudo apt-get update

    # The following address an issue in DO's Ubuntu images, which still contain a lock file
    sudo killall apt apt-get
    sudo rm /var/lib/dpkg/lock-frontend

    # Install docker and docker compose
    sudo apt-get install -y docker.io docker-compose-plugin

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
    SHELL
  end
    config.vm.provision "shell", inline: <<-SHELL
      # 1. Define the username and the public key
      TEAM_MEMBER="viktor"
      PUB_KEY="ssh-ed25519 AAAAC3Nza... paste_alices_actual_public_key_here alice@example.com"

      # 2. Create the user without prompting for a password
      sudo adduser --disabled-password --gecos "" $TEAM_MEMBER

      # 3. Create the SSH directory structure
      sudo mkdir -p /home/$TEAM_MEMBER/.ssh

      # 4. Add the public key to authorized_keys
      echo "$PUB_KEY" | sudo tee /home/$TEAM_MEMBER/.ssh/authorized_keys > /dev/null

      # 5. Set the strict SSH permissions (crucial!)
      sudo chown -R $TEAM_MEMBER:$TEAM_MEMBER /home/$TEAM_MEMBER/.ssh
      sudo chmod 700 /home/$TEAM_MEMBER/.ssh
      sudo chmod 600 /home/$TEAM_MEMBER/.ssh/authorized_keys

      # 6. Optional: Give them sudo (admin) and docker access
      sudo usermod -aG sudo,docker $TEAM_MEMBER
    SHELL
end

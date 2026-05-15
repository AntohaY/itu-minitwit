data "digitalocean_ssh_key" "deploy" {
  name = var.ssh_key_name
}

resource "digitalocean_project" "minitwit" {
  name        = var.project_name
  description = "MiniTwit infra managed by Terraform"
  environment = "Production"
  purpose     = "Web Application"

  resources = concat(
    [digitalocean_droplet.manager.urn],
    digitalocean_droplet.worker[*].urn,
    [digitalocean_database_cluster.mongo.urn],
  )
}

# ---------- Droplets ----------

resource "digitalocean_droplet" "manager" {
  name      = "minitwit"
  region    = var.region
  size      = var.droplet_size
  image     = var.droplet_image
  ssh_keys  = [data.digitalocean_ssh_key.deploy.id]
  user_data = file("${path.module}/cloud-init.yml")
  tags      = ["minitwit", "swarm-manager"]
}

resource "digitalocean_droplet" "worker" {
  count     = 2
  name      = "minitwit-web-${count.index + 1}"
  region    = var.region
  size      = var.droplet_size
  image     = var.droplet_image
  ssh_keys  = [data.digitalocean_ssh_key.deploy.id]
  user_data = file("${path.module}/cloud-init.yml")
  tags      = ["minitwit", "swarm-worker"]
}

# ---------- Cloud Firewall (replaces per-host ufw from Vagrantfile) ----------

resource "digitalocean_firewall" "swarm" {
  name = "minitwit-swarm"

  droplet_ids = concat(
    [digitalocean_droplet.manager.id],
    digitalocean_droplet.worker[*].id,
  )

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  inbound_rule {
    protocol         = "tcp"
    port_range       = "3000"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  inbound_rule {
    protocol         = "tcp"
    port_range       = "8080"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Swarm node-to-node communication, restricted to the cluster's own droplets.
  inbound_rule {
    protocol    = "tcp"
    port_range  = "2377"
    source_tags = ["minitwit"]
  }
  inbound_rule {
    protocol    = "tcp"
    port_range  = "7946"
    source_tags = ["minitwit"]
  }
  inbound_rule {
    protocol    = "udp"
    port_range  = "7946"
    source_tags = ["minitwit"]
  }
  inbound_rule {
    protocol    = "udp"
    port_range  = "4789"
    source_tags = ["minitwit"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# ---------- Managed MongoDB ----------

resource "digitalocean_database_cluster" "mongo" {
  name       = "minitwit-dbserver"
  engine     = "mongodb"
  version    = var.mongo_version
  size       = var.mongo_size
  region     = var.region
  node_count = var.mongo_node_count
}

resource "digitalocean_database_db" "minitwit" {
  cluster_id = digitalocean_database_cluster.mongo.id
  name       = var.mongo_db_name
}

# DO provider doesn't support the new user_settings field MongoDB requires,
# so we use the cluster's auto-created admin user (doadmin) instead.

resource "digitalocean_database_firewall" "mongo" {
  cluster_id = digitalocean_database_cluster.mongo.id

  dynamic "rule" {
    for_each = concat(
      [digitalocean_droplet.manager.id],
      digitalocean_droplet.worker[*].id,
    )
    content {
      type  = "droplet"
      value = rule.value
    }
  }
}

# DNS is hosted at Namecheap and managed manually — see infra/README.md
# for the cutover steps.

# ---------- Swarm bootstrap (runs after droplets exist) ----------
# Equivalent of setup-swarm.sh, but invoked via local-exec so it can
# orchestrate manager + workers from your laptop in a single pass.

resource "null_resource" "swarm" {
  depends_on = [
    digitalocean_droplet.manager,
    digitalocean_droplet.worker,
    digitalocean_firewall.swarm,
  ]

  triggers = {
    manager_id = digitalocean_droplet.manager.id
    worker_ids = join(",", digitalocean_droplet.worker[*].id)
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = "${path.module}/swarm-setup.sh"
    environment = {
      SSH_KEY        = pathexpand(var.ssh_private_key_path)
      MANAGER_IP     = digitalocean_droplet.manager.ipv4_address
      WORKER_IPS     = join(" ", digitalocean_droplet.worker[*].ipv4_address)
    }
  }
}

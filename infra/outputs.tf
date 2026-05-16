output "manager_ip" {
  description = "Public IPv4 of the swarm manager. Use this for SSH_HOST in GitHub Secrets."
  value       = digitalocean_droplet.manager.ipv4_address
}

output "worker_ips" {
  description = "Public IPv4s of the worker droplets."
  value       = digitalocean_droplet.worker[*].ipv4_address
}

output "mongo_uri" {
  description = "Full MongoDB connection string. Use for MONGO_URI in GitHub Secrets."
  value       = "mongodb+srv://${digitalocean_database_cluster.mongo.user}:${digitalocean_database_cluster.mongo.password}@${digitalocean_database_cluster.mongo.host}/${digitalocean_database_db.minitwit.name}?tls=true&authSource=admin"
  sensitive   = true
}

output "mongo_host" {
  description = "MongoDB cluster host."
  value       = digitalocean_database_cluster.mongo.host
}

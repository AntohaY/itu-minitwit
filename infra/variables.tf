variable "project_name" {
  type        = string
  description = "DigitalOcean project name to group resources under."
  default     = "minitwit"
}

variable "region" {
  type        = string
  description = "DigitalOcean region slug."
  default     = "fra1"
}

variable "droplet_image" {
  type        = string
  description = "Droplet OS image slug."
  default     = "ubuntu-22-04-x64"
}

variable "droplet_size" {
  type        = string
  description = "Droplet size slug."
  default     = "s-1vcpu-1gb"
}

variable "ssh_key_name" {
  type        = string
  description = "Name of the SSH key already registered in DigitalOcean."
  default     = "ssh_key_golang_minitwit"
}

variable "ssh_private_key_path" {
  type        = string
  description = "Local path to the matching SSH private key (used by remote-exec)."
  default     = "~/.ssh/ssh_key_golang_minitwit"
}

variable "tls_email" {
  type        = string
  description = "Email used for Let's Encrypt certificate registration."
}

variable "mongo_version" {
  type        = string
  description = "MongoDB engine version."
  default     = "7"
}

variable "mongo_size" {
  type        = string
  description = "MongoDB managed cluster size slug."
  default     = "db-s-1vcpu-1gb"
}

variable "mongo_node_count" {
  type        = number
  description = "Number of nodes in the MongoDB cluster (1 = single, 3 = HA)."
  default     = 1
}

variable "mongo_db_name" {
  type        = string
  description = "Application database name inside the MongoDB cluster."
  default     = "minitwit"
}

variable "docker_username" {
  type        = string
  description = "Docker Hub username whose images will be deployed."
  default     = "antohay"
}

variable "discord_token" {
  type        = string
  description = "Discord bot token passed to the bot service."
  sensitive   = true
}

variable "grafana_admin_user" {
  type        = string
  description = "Grafana admin username."
  default     = "admin"
}

variable "grafana_admin_password" {
  type        = string
  description = "Grafana admin password."
  sensitive   = true
}

variable "cookie_secure" {
  type        = string
  description = "Set to 'false' to allow session cookies over HTTP (test only). Default 'true' for production HTTPS."
  default     = "true"
}

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.43"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}

provider "digitalocean" {
  # Reads token from DIGITALOCEAN_TOKEN env var automatically.
  # Export it before running terraform: export DIGITALOCEAN_TOKEN=...
}

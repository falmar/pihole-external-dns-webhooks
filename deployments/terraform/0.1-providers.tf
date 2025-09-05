provider "helm" {
  kubernetes = {
    config_path = var.kubeconfig_path
  }
}

provider "kubernetes" {
  config_path = var.kubeconfig_path
}

terraform {
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 3"
    }
    sops = {
      source  = "carlpett/sops"
      version = "1.2.1"
    }
  }
}

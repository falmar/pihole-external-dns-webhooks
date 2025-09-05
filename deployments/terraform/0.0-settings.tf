locals {
  domain = "kind.local"
}

variable "cluster_name" {
  type = string
  default = "pihole-stack"
}

variable "kubeconfig_path" {
  default = "~/.kube/kind"
}

variable "k8sServiceHost" {
  type = string
  default = "pihole-stack-control-plane"
}

variable "skip_oauth_setup" {
  type = bool
  default = false
}

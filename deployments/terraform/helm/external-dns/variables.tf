terraform {
  required_providers {
    sops = {
      source = "carlpett/sops"
    }
  }
}

variable "namespace" {
  type = string
}

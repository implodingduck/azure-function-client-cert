variable "subscription_id" {
  type = string
  sensitive = true
}

variable "location" {
  type    = string
  default = "East US"
}

variable "gh_repo" {
  type = string
}

variable "subject_cn" {
  type = string
}

variable "issuer_cn" {
  type = string
}
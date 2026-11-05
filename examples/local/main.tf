variable "port" {
  type    = number
  default = 2222
}

module "trufflehog" {
  source = "../.."

  hosts                = { box = "127.0.0.1" }
  ssh_port             = var.port
  ssh_private_key_file = "./id_ed25519"
  ssh_known_hosts_file = "./known_hosts"

  targets       = ["/etc", "/home", "/root", "/opt", "/srv"]
  exclude_paths = ["^/etc/ssh/ssh_host_.*_key$"]
  verify        = false
  schedule      = "daily"
  keep          = 4
}

output "summary" {
  value = module.trufflehog.summary
}

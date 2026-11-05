output "results_dir" {
  description = "Directory on each host that holds one directory per scan, newest linked as latest. Null when targets is empty."
  value       = length(var.targets) > 0 ? local.results_dir : null
}

output "summary" {
  description = "Count of findings by detector and verification from the latest scan on each host. Null when targets is empty."
  value       = length(var.targets) > 0 ? "${local.results_dir}/latest/summary.txt" : null
}

output "findings" {
  description = "Findings of the latest scan, one JSON object per line. Each holds the secret it found. Null when targets is empty."
  value       = length(var.targets) > 0 ? "${local.results_dir}/latest/findings.json" : null
}

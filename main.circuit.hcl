# Facts give each host's architecture, which picks the release tarball, and
# its distribution.
data "conn3x_host" "facts" {
  for_each = var.hosts

  ssh {
    host             = try(each.value.address, each.value)
    host_key         = try(each.value.host_key, null)
    user             = try(each.value.user, var.ssh_user)
    port             = try(each.value.port, var.ssh_port)
    private_key_file = try(each.value.private_key_file, var.ssh_private_key_file)
    jump_hosts       = try(each.value.jump_hosts, null)
    known_hosts_file = var.ssh_known_hosts_file
  }

  lifecycle {
    postcondition {
      condition     = (self.os_id == "ubuntu" && self.os_version == "24.04") || (self.os_id == "debian" && self.os_version == "13") || (self.os_id == "rocky" && startswith(self.os_version, "10.")) || (self.os_id == "fedora" && self.os_version == "45")
      error_message = "Host ${each.key} runs ${self.os_id} ${self.os_version}. This circuit supports Ubuntu 24.04, Debian 13, Rocky Linux 10 and Fedora 45."
    }
    postcondition {
      condition     = contains(["x86_64", "aarch64"], self.arch)
      error_message = "Host ${each.key} is ${self.arch}. TruffleHog publishes Linux builds for x86_64 and aarch64 only."
    }
  }
}

locals {
  goarch = { x86_64 = "amd64", aarch64 = "arm64" }

  home        = "/opt/trufflehog/${var.trufflehog_version}"
  tarball     = "/opt/trufflehog/trufflehog_${var.trufflehog_version}.tar.gz"
  results_dir = "/var/lib/conn3x-trufflehog"
  exclude     = "/etc/conn3x-trufflehog/exclude"
  script      = "/usr/local/sbin/conn3x-trufflehog"
  unit        = "conn3x-trufflehog"

  # The scan steps exist only when there is something to scan.
  scan = toset(length(var.targets) > 0 ? ["scan"] : [])

  # Reports hold the secrets they found, so a scan that reached them would
  # find every secret again.
  exclude_paths = concat(["^${replace(local.results_dir, ".", "\\.")}/"], var.exclude_paths)

  flags = join(" ", compact([
    "--no-update",
    "--json",
    "--exclude-paths=${local.exclude}",
    "--results=${join(",", var.results)}",
    var.verify ? "" : "--no-verification",
  ]))

  run_script = <<-EOT
    #!/bin/sh
    # Written by Conn3x. Changes here are overwritten on the next apply.
    # Scans ${join(" ", var.targets)} for secrets and writes the findings to a
    # new directory under ${local.results_dir}, then points latest at it.
    set -eu
    umask 077
    # TruffleHog logs a missing path and carries on, which would read as a
    # clean scan.
    for t in ${join(" ", var.targets)}; do
      [ -e "$t" ] || { echo "$t doesn't exist." >&2; exit 1; }
    done
    dir=${local.results_dir}
    run=$(date -u +%Y%m%dT%H%M%SZ)
    mkdir -p "$dir/$run"
    /usr/local/bin/trufflehog filesystem ${local.flags} \
      ${join(" ", var.targets)} > "$dir/$run/findings.json" 2> "$dir/$run/trufflehog.log" || {
        tail -n 20 "$dir/$run/trufflehog.log" >&2
        exit 1
      }
    # One line per finding: the detector, and whether TruffleHog confirmed the
    # secret works.
    sed -n -E 's/.*"DetectorName":"([^"]*)".*"Verified":(true|false).*/\1 \2/p' "$dir/$run/findings.json" \
      | sed -e 's/ true$/ verified/' -e 's/ false$/ unverified/' | sort | uniq -c | awk '{ print $2, $3, $1 }' > "$dir/$run/summary.txt"
    ln -sfn "$run" "$dir/latest"
    find "$dir" -mindepth 1 -maxdepth 1 -type d -name '2*' | sort | head -n -${var.keep} | xargs -r rm -rf
    echo "$(wc -l < "$dir/$run/findings.json") findings"
    cat "$dir/$run/summary.txt"
  EOT
}

circuit "trufflehog" {
  hosts = var.hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "tools" {
    for_each = toset(["curl", "tar", "gzip"])
    package {
      name = item.value
    }
  }

  # The tarball from the release, not the install script on trufflehog's
  # site or a package manager: a version and a checksum fixed here can't
  # change under you.
  step "download" {
    download {
      url    = "https://github.com/trufflesecurity/trufflehog/releases/download/v${var.trufflehog_version}/trufflehog_${var.trufflehog_version}_linux_${local.goarch[data.conn3x_host.facts[each.key].arch]}.tar.gz"
      sha256 = var.checksums[local.goarch[data.conn3x_host.facts[each.key].arch]]
      dest   = local.tarball
    }
  }

  step "unpack" {
    archive {
      src     = local.tarball
      dest    = local.home
      creates = "${local.home}/trufflehog"
    }
  }

  step "link" {
    link {
      path   = "/usr/local/bin/trufflehog"
      target = "${local.home}/trufflehog"
    }
  }

  # Findings hold the secrets themselves, so only root reads them.
  step "results_dir" {
    for_each = local.scan
    directory {
      path = local.results_dir
      mode = "0700"
    }
  }

  step "exclude_dir" {
    for_each = local.scan
    directory {
      path = "/etc/conn3x-trufflehog"
      mode = "0755"
    }
  }

  step "exclude" {
    for_each = local.scan
    file {
      path    = local.exclude
      content = "${join("\n", local.exclude_paths)}\n"
    }
  }

  step "script" {
    for_each = local.scan
    file {
      path    = local.script
      content = local.run_script
      mode    = "0755"
    }
  }

  step "schedule_valid" {
    for_each = local.scan
    command {
      command = "echo 'schedule is not a calendar expression systemd understands: ${var.schedule}' >&2; exit 1"
      unless  = "systemd-analyze calendar '${var.schedule}' >/dev/null"
    }
  }

  # The scan runs as root so it can read everything. This holds it to
  # reading: the whole host is read-only to it but its results directory,
  # and the one capability it keeps is reading past file permissions.
  step "sandbox" {
    for_each = local.scan
    file {
      path    = "/etc/systemd/system/${local.unit}.service.d/sandbox.conf"
      content = <<-EOT
        [Service]
        ProtectSystem=strict
        ReadWritePaths=${local.results_dir}
        PrivateTmp=true
        NoNewPrivileges=true
        CapabilityBoundingSet=CAP_DAC_READ_SEARCH
        Nice=19
        IOSchedulingClass=idle
      EOT
    }
  }

  step "sandbox_applied" {
    for_each = local.scan
    command {
      command  = "systemctl daemon-reload"
      triggers = { sandbox = conn3x_file.trufflehog__sandbox["${each.key}/scan"].revision }
    }
  }

  step "timer" {
    for_each = local.scan
    timer {
      name        = local.unit
      description = "TruffleHog secret scan"
      on_calendar = var.schedule
      command     = local.script
      persistent  = true
    }
  }

  step "run" {
    for_each = toset(length(var.targets) > 0 && var.run_now ? ["scan"] : [])
    command {
      command = "systemctl start ${local.unit}.service"
      triggers = {
        script  = conn3x_file.trufflehog__script["${each.key}/scan"].revision
        exclude = conn3x_file.trufflehog__exclude["${each.key}/scan"].revision
      }
    }
  }
}

variable "hosts" {
  type        = any
  description = "Hosts to configure: a map of names to addresses, or to host objects with an address and optional host_key, user, port, private_key_file or jump_hosts."
}

variable "ssh_user" {
  type        = string
  default     = "root"
  description = "User to log in as."
}

variable "ssh_port" {
  type        = number
  default     = 22
  description = "SSH port."
}

variable "ssh_private_key_file" {
  type        = string
  default     = null
  description = "Path to a private key. When null, Conn3x uses the SSH agent."
}

variable "ssh_known_hosts_file" {
  type        = string
  default     = null
  description = "known_hosts file to check host keys against. When null, ~/.ssh/known_hosts."
}

variable "ssh_become" {
  type        = bool
  default     = false
  description = "Run commands as root through sudo."
}

variable "trufflehog_version" {
  type        = string
  default     = "3.99.8"
  description = "TruffleHog release to install from GitHub. Change checksums with it."

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.trufflehog_version))
    error_message = "trufflehog_version is a release number such as \"3.99.8\"."
  }
}

variable "checksums" {
  type        = map(string)
  description = "SHA-256 of the release tarball for each architecture, from the release's trufflehog_<version>_checksums.txt. Change these with trufflehog_version."
  default = {
    amd64 = "7c3b02f160f28929a467e29e20fba98746e0729f6e37c3c25761e4f8789abe08"
    arm64 = "a0382d83dd58c967af5dd0175cc732c62c836ab1d15dc9ae71b01a2d3f0911b2"
  }

  validation {
    condition     = alltrue([for a in ["amd64", "arm64"] : can(regex("^[0-9a-f]{64}$", var.checksums[a]))])
    error_message = "checksums needs a SHA-256, as 64 lowercase hex digits, for both amd64 and arm64."
  }
}

variable "targets" {
  type        = list(string)
  default     = []
  description = "Absolute paths to scan on a timer, all in one report. When empty, the circuit installs TruffleHog and sets up no scan."

  validation {
    condition     = alltrue([for t in var.targets : can(regex("^/[A-Za-z0-9._/-]*$", t))])
    error_message = "targets is a list of absolute paths, using letters, digits and . _ - /."
  }

  # /proc and /sys aren't files, and TruffleHog would read them forever.
  validation {
    condition     = !contains(var.targets, "/")
    error_message = "targets can't be \"/\". List the directories that hold files worth scanning, such as \"/etc\", \"/home\" and \"/srv\"."
  }
}

variable "exclude_paths" {
  type        = list(string)
  default     = []
  description = "Regular expressions for files to leave out, matched against each file's absolute path, such as \"^/srv/backups/\" or \"\\\\.log$\"."

  validation {
    condition     = alltrue([for p in var.exclude_paths : can(regexall(p, "")) && !strcontains(p, "\n")])
    error_message = "Each of exclude_paths is a single-line regular expression in Go's syntax."
  }
}

variable "verify" {
  type        = bool
  default     = true
  description = "Check each secret found against the service it belongs to, as TruffleHog does by default. This sends the secret to that service. False only reports what each detector matched."
}

variable "results" {
  type        = list(string)
  default     = ["verified", "unknown", "unverified"]
  description = "Which findings to report, from verified, unknown (verification failed with an error) and unverified."

  validation {
    condition     = length(var.results) > 0 && alltrue([for r in var.results : contains(["verified", "unknown", "unverified"], r)])
    error_message = "results is a list of one or more of verified, unknown and unverified."
  }
}

variable "schedule" {
  type        = string
  default     = "daily"
  description = "When the scan timer runs, as a systemd OnCalendar expression such as \"daily\" or \"Sun 03:00\"."

  validation {
    condition     = !strcontains(var.schedule, "\n") && !strcontains(var.schedule, "'")
    error_message = "schedule is a single-line systemd calendar expression."
  }
}

variable "keep" {
  type        = number
  default     = 7
  description = "Number of scans to keep under /var/lib/conn3x-trufflehog. Older ones are deleted after each scan."

  validation {
    condition     = var.keep >= 1 && floor(var.keep) == var.keep
    error_message = "keep must be a whole number, 1 or more."
  }
}

variable "run_now" {
  type        = bool
  default     = false
  description = "Scan during the apply: on the first apply, and again whenever the scan's settings change. Needs targets."
}

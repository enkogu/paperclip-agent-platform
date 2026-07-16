variable "account_id" {
  description = "Cloudflare account identifier."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{32}$", var.account_id))
    error_message = "account_id must be a 32-character Cloudflare identifier."
  }
}

variable "zone_id" {
  description = "Cloudflare zone identifier that contains base_domain."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{32}$", var.zone_id))
    error_message = "zone_id must be a 32-character Cloudflare identifier."
  }
}

variable "base_domain" {
  description = "Base DNS name under which platform services are published."
  type        = string

  validation {
    condition = (
      length(var.base_domain) <= 253 &&
      can(regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", var.base_domain))
    )
    error_message = "base_domain must be a lowercase DNS name without a scheme or trailing dot."
  }
}

variable "tunnel_name" {
  description = "Stable name of the remotely managed Cloudflare Tunnel."
  type        = string

  validation {
    condition     = length(trimspace(var.tunnel_name)) > 0
    error_message = "tunnel_name cannot be empty."
  }
}

variable "apps" {
  description = "Published platform applications keyed by stable component ID."
  type = map(object({
    hostname     = string
    origin       = string
    access_class = string
  }))

  validation {
    condition     = length(var.apps) > 0
    error_message = "At least one application exposure is required."
  }

  validation {
    condition = alltrue([
      for app in values(var.apps) : contains(["human", "service"], app.access_class)
    ])
    error_message = "Every app access_class must be either human or service."
  }

  validation {
    condition = alltrue([
      for app in values(var.apps) : endswith(app.hostname, ".${var.base_domain}")
    ])
    error_message = "Every app hostname must be a child of base_domain."
  }

  validation {
    condition = alltrue([
      for app in values(var.apps) : can(regex("^https?://(127\\.0\\.0\\.1|localhost|\\[::1\\])(?::[0-9]{1,5})?(?:/.*)?$", app.origin))
    ])
    error_message = "Every origin must be an HTTP(S) loopback URL reachable by host-network cloudflared."
  }
}

variable "human_allowed_emails" {
  description = "Exact identities allowed to access human-facing applications."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for email in var.human_allowed_emails : can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", email))
    ])
    error_message = "Every human_allowed_emails item must be an email address."
  }
}

variable "human_session_duration" {
  description = "Lifetime of a human Cloudflare Access session."
  type        = string

  validation {
    condition     = can(regex("^[1-9][0-9]*(?:ms|s|m|h)$", var.human_session_duration))
    error_message = "human_session_duration must use a Cloudflare duration such as 12h or 30m."
  }
}

variable "service_token_duration" {
  description = "Lifetime of the platform-to-platform Cloudflare Access service token."
  type        = string

  validation {
    condition     = can(regex("^[1-9][0-9]*(?:ms|s|m|h)$", var.service_token_duration))
    error_message = "service_token_duration must use a Cloudflare duration such as 8760h."
  }
}

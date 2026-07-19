terraform {
  required_version = ">= 1.5.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "= 5.21.1"
    }
  }
}

# The provider intentionally reads CLOUDFLARE_API_TOKEN from the process
# environment. The API credential must never be written to tfvars or state.
provider "cloudflare" {}

locals {
  human_apps = {
    for id, app in var.apps : id => app if app.access_class == "human"
  }
  service_apps = {
    for id, app in var.apps : id => app if app.access_class == "service"
  }

  # A remotely managed tunnel requires the final catch-all rule. Giving the
  # fallback a null hostname keeps every list item the same object type.
  ingress = concat(
    [for id in sort(keys(var.apps)) : {
      hostname = var.apps[id].hostname
      service  = var.apps[id].origin
    }],
    [{
      hostname = null
      service  = "http_status:404"
    }]
  )
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "platform" {
  account_id = var.account_id
  name       = var.tunnel_name
  config_src = "cloudflare"
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "platform" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.platform.id
  source     = "cloudflare"

  config = {
    ingress = local.ingress
  }
}

data "cloudflare_zero_trust_tunnel_cloudflared_token" "platform" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.platform.id
}

# DNS has a separate batch reconciler because the Cloudflare API guarantees one
# database transaction for deletes + posts. Forget legacy per-record provider
# ownership without destroying records one by one; server-cloudflare-dns.py
# then replaces reserved shipped hostnames in one fail-closed batch request.
removed {
  from = cloudflare_dns_record.platform

  lifecycle {
    destroy = false
  }
}

resource "cloudflare_zero_trust_access_policy" "human" {
  count = length(local.human_apps) > 0 ? 1 : 0

  account_id = var.account_id
  name       = "MTE platform human operators"
  decision   = "allow"
  include = [
    for email in sort(tolist(var.human_allowed_emails)) : {
      email = {
        email = email
      }
    }
  ]

  lifecycle {
    precondition {
      condition     = length(var.human_allowed_emails) > 0
      error_message = "Human-facing apps require at least one exact allowed email."
    }
  }
}

resource "cloudflare_zero_trust_access_service_token" "service" {
  for_each = local.service_apps

  account_id = var.account_id
  name       = "MTE ${each.key} service client"
  duration   = var.service_token_duration

  lifecycle {
    create_before_destroy = true
  }
}

resource "cloudflare_zero_trust_access_policy" "service" {
  for_each = local.service_apps

  account_id = var.account_id
  name       = "MTE ${each.key} service authentication"
  decision   = "non_identity"
  include = [{
    service_token = {
      token_id = cloudflare_zero_trust_access_service_token.service[each.key].id
    }
  }]
}

# Cloudflare provider v5 can POST an Access application but then wait forever
# before writing Terraform state.  The platform's fixed Access app set is
# therefore reconciled with Cloudflare's documented REST endpoint by
# server-cloudflare-access.py.  Terraform remains the owner of the tunnel,
# policies, and per-route service tokens it supplies to that reconciler.

# Existing test deployments may have partial v5 app state from a stalled
# create. Forget it without deleting the remote application; the REST
# reconciler adopts it on the next apply. Fresh deployments have no entries.
removed {
  from = cloudflare_zero_trust_access_application.human

  lifecycle {
    destroy = false
  }
}

removed {
  from = cloudflare_zero_trust_access_application.service

  lifecycle {
    destroy = false
  }
}

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

resource "cloudflare_dns_record" "platform" {
  for_each = var.apps

  zone_id = var.zone_id
  name    = each.value.hostname
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.platform.id}.cfargotunnel.com"
  ttl     = 1
  proxied = true
  comment = "Managed by MTE platform IaC for ${each.key}"
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

resource "cloudflare_zero_trust_access_service_token" "platform" {
  count = length(local.service_apps) > 0 ? 1 : 0

  account_id = var.account_id
  name       = "MTE platform service clients"
  duration   = var.service_token_duration

  lifecycle {
    create_before_destroy = true
  }
}

resource "cloudflare_zero_trust_access_policy" "service" {
  count = length(local.service_apps) > 0 ? 1 : 0

  account_id = var.account_id
  name       = "MTE platform service authentication"
  decision   = "non_identity"
  include = [{
    service_token = {
      token_id = cloudflare_zero_trust_access_service_token.platform[0].id
    }
  }]
}

resource "cloudflare_zero_trust_access_application" "human" {
  for_each = local.human_apps

  account_id = var.account_id
  name       = "MTE ${each.key}"
  domain     = each.value.hostname
  type       = "self_hosted"
  destinations = [{
    type = "public"
    uri  = each.value.hostname
  }]
  session_duration           = var.human_session_duration
  app_launcher_visible       = true
  enable_binding_cookie      = true
  http_only_cookie_attribute = true
  same_site_cookie_attribute = "strict"
  policies = [{
    id         = cloudflare_zero_trust_access_policy.human[0].id
    precedence = 1
  }]
}

resource "cloudflare_zero_trust_access_application" "service" {
  for_each = local.service_apps

  account_id = var.account_id
  name       = "MTE ${each.key} service"
  domain     = each.value.hostname
  type       = "self_hosted"
  destinations = [{
    type = "public"
    uri  = each.value.hostname
  }]
  app_launcher_visible      = false
  service_auth_401_redirect = true
  policies = [{
    id         = cloudflare_zero_trust_access_policy.service[0].id
    precedence = 1
  }]
}

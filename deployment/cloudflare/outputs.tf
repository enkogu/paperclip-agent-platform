output "tunnel" {
  description = "Non-secret tunnel identity and DNS target."
  value = {
    id         = cloudflare_zero_trust_tunnel_cloudflared.platform.id
    name       = cloudflare_zero_trust_tunnel_cloudflared.platform.name
    dns_target = "${cloudflare_zero_trust_tunnel_cloudflared.platform.id}.cfargotunnel.com"
  }
}

output "published_hostnames" {
  description = "Hostnames declared by this stack and reconciled through the DNS batch API."
  value = {
    for id, app in var.apps : id => app.hostname
  }
}

output "tunnel_id" {
  description = "Non-secret tunnel identifier consumed by the DNS batch reconciler."
  value       = cloudflare_zero_trust_tunnel_cloudflared.platform.id
}

output "human_access_policy_id" {
  description = "Non-secret policy ID consumed by the Access API reconciler."
  value       = try(cloudflare_zero_trust_access_policy.human[0].id, null)
}

output "service_access_policy_ids" {
  description = "Per-application policy IDs consumed by the Access API reconciler."
  value = {
    for id, policy in cloudflare_zero_trust_access_policy.service : id => policy.id
  }
}

# Terraform/OpenTofu masks sensitive outputs during plan/apply. Deployment code
# must capture these values without echoing them and write them directly to a
# root-only secret store. They remain sensitive data in the IaC state file.
output "tunnel_token" {
  description = "Credential consumed by cloudflared on the target host."
  value       = data.cloudflare_zero_trust_tunnel_cloudflared_token.platform.token
  sensitive   = true
}

output "service_tokens" {
  description = "Per-application credentials used only by the matching service route."
  value = {
    for id, token in cloudflare_zero_trust_access_service_token.service : id => {
      id            = token.id
      client_id     = token.client_id
      client_secret = token.client_secret
      expires_at    = token.expires_at
    }
  }
  sensitive = true
}

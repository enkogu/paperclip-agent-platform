output "tunnel" {
  description = "Non-secret tunnel identity and DNS target."
  value = {
    id         = cloudflare_zero_trust_tunnel_cloudflared.platform.id
    name       = cloudflare_zero_trust_tunnel_cloudflared.platform.name
    dns_target = "${cloudflare_zero_trust_tunnel_cloudflared.platform.id}.cfargotunnel.com"
  }
}

output "published_hostnames" {
  description = "Hostnames managed by this stack, keyed by component ID."
  value = {
    for id, record in cloudflare_dns_record.platform : id => record.name
  }
}

output "access_applications" {
  description = "Access application identifiers and audience tags."
  value = merge(
    {
      for id, app in cloudflare_zero_trust_access_application.human : id => {
        id           = app.id
        audience_tag = app.aud
        class        = "human"
      }
    },
    {
      for id, app in cloudflare_zero_trust_access_application.service : id => {
        id           = app.id
        audience_tag = app.aud
        class        = "service"
      }
    }
  )
}

# Terraform/OpenTofu masks sensitive outputs during plan/apply. Deployment code
# must capture these values without echoing them and write them directly to a
# root-only secret store. They remain sensitive data in the IaC state file.
output "tunnel_token" {
  description = "Credential consumed by cloudflared on the target host."
  value       = data.cloudflare_zero_trust_tunnel_cloudflared_token.platform.token
  sensitive   = true
}

output "service_token" {
  description = "Credential used by automated clients of service-class apps."
  value = length(cloudflare_zero_trust_access_service_token.platform) == 1 ? {
    id            = cloudflare_zero_trust_access_service_token.platform[0].id
    client_id     = cloudflare_zero_trust_access_service_token.platform[0].client_id
    client_secret = cloudflare_zero_trust_access_service_token.platform[0].client_secret
    expires_at    = cloudflare_zero_trust_access_service_token.platform[0].expires_at
  } : null
  sensitive = true
}

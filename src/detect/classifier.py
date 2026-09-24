"""Service classification: refine 'generic' rule hits using context hints."""
from __future__ import annotations

SERVICE_HINTS: dict[str, tuple[str, ...]] = {
    "aws": ("aws", "amazon", "s3", "ec2", "lambda", "dynamodb"),
    "google": ("google", "gcp", "googleapis", "gcm", "gms"),
    "firebase": ("firebase", "firestore"),
    "stripe": ("stripe",),
    "twilio": ("twilio",),
    "sendgrid": ("sendgrid",),
    "mailgun": ("mailgun",),
    "github": ("github", "gh_"),
    "slack": ("slack",),
    "openai": ("openai",),
    "anthropic": ("anthropic", "claude"),
    "shopify": ("shopify", "myshopify"),
    "paypal": ("paypal",),
    "square": ("squareup", "square"),
    "heroku": ("heroku",),
    "digitalocean": ("digitalocean", "do_spaces"),
    "cloudflare": ("cloudflare",),
    "supabase": ("supabase",),
    "mapbox": ("mapbox",),
    "algolia": ("algolia",),
    "onesignal": ("onesignal",),
    "pusher": ("pusher",),
    "braze": ("braze",),
    "amplitude": ("amplitude",),
    "sentry": ("sentry.io", "sentry"),
    "datadog": ("datadog",),
    "mongo": ("mongodb", "mongo"),
    "redis": ("redis",),
    "mysql": ("mysql",),
    "postgres": ("postgres",),
}


def refine_service(rule_service: str, context: str) -> str:
    """Rules fire on format; when the rule is generic, infer the service
    from nearby code context. Never touches the network — purely passive."""
    if rule_service != "generic":
        return rule_service
    low = context.lower()
    for service, hints in SERVICE_HINTS.items():
        if any(h in low for h in hints):
            return service
    return "generic"

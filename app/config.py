from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    redis_url: str = "redis://localhost:6379/0"

    doh_url: str = "https://cloudflare-dns.com/dns-query"
    rdap_url: str = "https://rdap.nic.ru/domain"
    whois_host: str = "whois.tcinet.ru"
    whois_port: int = 43

    doh_rps: float = 50.0
    rdap_rps: float = 3.0
    whois_rps: float = 0.5

    http_timeout: float = 10.0
    whois_timeout: float = 10.0

    batch_max_size: int = 10_000
    worker_concurrency: int = 32

    ttl_free: int = 300
    ttl_registered: int = 86_400
    ttl_pending: int = 60
    ttl_error: int = 300
    ttl_unknown: int = 60
    ttl_doh: int = 600

    log_level: str = "INFO"


settings = Settings()

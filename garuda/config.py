from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """GARUDA Platform Configuration & Threat Detection Constants."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Application Configuration
    APP_NAME: str = "GARUDA Threat Intelligence Platform"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    API_PREFIX: str = "/api/v1"
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
    ]

    # Database & Supabase Settings
    SUPABASE_URL: Optional[str] = "https://sulnilwykmrosirbdvil.supabase.co"
    SUPABASE_KEY: Optional[str] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN1bG5pbHd5a21yb3NpcmJkdmlsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODc3OTQ4NDksImV4cCI6MjEwMzM3MDg0OX0.HMdCMiBUNWOv3PdF8LfLVu5O7ku4eciJElrximhDlAo"
    SUPABASE_SERVICE_ROLE_KEY: Optional[str] = None
    DATABASE_URL: Optional[str] = None

    # Redis & Celery Settings
    REDIS_URL: Optional[str] = None
    UPSTASH_REDIS_REST_URL: Optional[str] = "https://sure-gorilla-108961.upstash.io"
    UPSTASH_REDIS_REST_TOKEN: Optional[str] = "gQAAAAAAAamhAAIgcDFlMjUxNTJjNzI1NjQ0ODQ0ODI2NjI0NjY4ZTg4YzUwMQ"
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None

    # AI & Threat Narrative Engine
    ANTHROPIC_API_KEY: Optional[str] = None

    # Threat Intelligence Feeds & OSINT APIs
    OTX_API_KEY: Optional[str] = None
    CIRCL_API_USER: Optional[str] = None
    CIRCL_API_PASSWORD: Optional[str] = None
    URLHAUS_API_KEY: Optional[str] = None
    URLHAUS_TOKEN: Optional[str] = None
    PHISHTANK_KEY: Optional[str] = None
    ABUSEIPDB_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = "f80317b707c964a757e92fb6188bc509fae57749a14908eff8bc73fb1504ddfd"
    SHODAN_API_KEY: Optional[str] = "ItNBJkUPHLzH6Cmm34QZSHjYVMRz0DnN"
    SECURITYTRAILS_API_KEY: Optional[str] = None
    WHOISXML_API_KEY: Optional[str] = "at_gc7Jzm8An7sC8lLcfGdSs8qk1OUKl"

    # GitHub Actions Integration (Background Dispatch & Playwright Offloading)
    GH_TOKEN: Optional[str] = None
    GH_REPO: Optional[str] = "singhharsimar23-dotcom/garuda"

    # Geopolitical Tension & Conflict Monitoring
    GDELT_API_KEY: Optional[str] = None
    TENSION_FEED_URL: Optional[str] = None
    CONFLICT_MODE: bool = False
    TENSION_THRESHOLD: float = 0.65
    CRON_SECRET: Optional[str] = None

    # Webhook Alerts
    SLACK_WEBHOOK_URL: Optional[str] = None
    TEAMS_WEBHOOK_URL: Optional[str] = None
    TELEGRAM_BOT_TOKEN: Optional[str] = "8306024525:AAEiEjrkqsv3UzQD-f7l9MRn41dsBpwjCE8"
    TELEGRAM_CHAT_ID: Optional[str] = "6433246026"

    # Threat Scoring Thresholds
    SCORE_THRESHOLD_LOG: int = 40
    SCORE_THRESHOLD_MEDIUM: int = 70
    SCORE_THRESHOLD_CRITICAL: int = 85

    # APT36 Infrastructure Signatures & Detection Constants
    APT36_SUSPICIOUS_TLDS: List[str] = [
        ".space",
        ".online",
        ".site",
        ".xyz",
        ".cv",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".info",
        ".pw",
    ]

    APT36_HOSTING_ASNS: List[int] = [
        16276,  # OVH
        24940,  # Hetzner
        63949,  # Linode / Akamai
        14061,  # DigitalOcean
        20473,  # Vultr / Choopa
    ]

    APT36_C2_PORTS: List[int] = [4000, 8443, 9001]

    APT36_JA3_HASHES: List[str] = [
        "51c64c77e60f3980eea90869b68c58a8",  # CrimsonRAT — CIRCL profile
        "a0e9f5d64349fb13191bc781f81f42e1",  # DeskRAT C2 — Recorded Future 2024
        "6734f37431109a4e8b2eca26639d2852",  # StealthMango — Seqrite 2023
        "c12f54a3f91dc7bafd92cb59fe009a35",  # ObliqueRAT — Morphisec 2021
    ]

    # Tier 1 Priority Keyword Patterns (Exact 85 Target Patterns)
    TIER_1_PATTERNS: List[str] = [
        "modgov",
        "mod-india",
        "modindia",
        "defencein",
        "defenceindia",
        "raksha",
        "mantralaya",
        "rakshamantralaya",
        "nicin",
        "nic-in",
        "nicmail",
        "nicwebmail",
        "webmailnic",
        "niclogin",
        "nic-login",
        "nicindia",
        "indianarmy",
        "army-hq",
        "armyhq",
        "armyindia",
        "indiannavy",
        "navyindia",
        "iafin",
        "iaf-india",
        "airforceindia",
        "cds-india",
        "cdsindia",
        "hq-ids",
        "hqids",
        "drdo",
        "drdolab",
        "drdoresearch",
        "cair",
        "dlrl",
        "gtre",
        "diat",
        "mceme",
        "cer-drdo",
        "isroin",
        "isro-india",
        "bsf-india",
        "crpfindia",
        "ntro-in",
        "rawmail",
        "ibindia",
        "hqwesternair",
        "hqeasternair",
        "hqsouthernair",
        "hqtraining",
        "southernnaval",
        "easternnaval",
        "westernnaval",
        "andamannaval",
        "defenceresearch",
        "defenceprocurement",
        "pmoindia",
        "cabinetindia",
        "ministryexternal",
        "meaindia",
        "homeaffairs",
        "financemin",
        "cbiin",
        "incoin",
        "sebi-india",
        "nabarindia",
        "rdbiindia",
        "rbi-india",
        "npclindia",
        "uidaiin",
        "uidai-india",
        "covindia",
        "irctclogin",
        "railindia",
    ]

    # Tier 2 Secondary Strategic & Infrastructure Patterns (25 Patterns)
    TIER_2_PATTERNS: List[str] = [
        "hal-india",
        "bel-india",
        "bdl-india",
        "mazagondock",
        "cochinshipyard",
        "grse-india",
        "midhani",
        "ongcindia",
        "iocl-india",
        "bpcl-india",
        "ntpcindia",
        "powergridindia",
        "barc-india",
        "npcil-india",
        "aerodynamics",
        "bsnl-india",
        "mtnl-india",
        "epfindia",
        "incometaxindia",
        "cbic-india",
        "parliamentofindia",
        "supremecourtofindia",
        "cert-in",
        "nciipc",
        "cdac-india",
    ]


settings = Settings()

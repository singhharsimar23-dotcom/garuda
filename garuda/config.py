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
    ENVIRONMENT: str = "production"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    API_PREFIX: str = "/api/v1"
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "https://garuda-ochre.vercel.app",
    ]

    # Database & Supabase Settings
    SUPABASE_URL: Optional[str] = "https://sulnilwykmrosirbdvil.supabase.co"
    SUPABASE_KEY: Optional[str] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN1bG5pbHd5a21yb3NpcmJkdmlsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODc3OTQ4NDksImV4cCI6MjEwMzM3MDg0OX0.HMdCMiBUNWOv3PdF8LfLVu5O7ku4eciJElrximhDlAo"
    SUPABASE_SERVICE_ROLE_KEY: Optional[str] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN1bG5pbHd5a21yb3NpcmJkdmlsIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4Nzc5NDg0OSwiZXhwIjoyMTAzMzcwODQ5fQ.QERsqi2Z-f_G1CrjLRd2IaoScMw1vJSqfHYKZPD8ERo"
    DATABASE_URL: Optional[str] = None

    # Redis & Celery Settings
    REDIS_URL: Optional[str] = None
    UPSTASH_REDIS_REST_URL: Optional[str] = "https://sure-gorilla-108961.upstash.io"
    UPSTASH_REDIS_REST_TOKEN: Optional[str] = "gQAAAAAAAamhAAIgcDFlMjUxNTJjNzI1NjQ0ODQ0ODI2NjI0NjY4ZTg4YzUwMQ"
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None

    # AI & Threat Narrative Engine (Google Gemini)
    GEMINI_API_KEY: Optional[str] = None

    # Threat Intelligence Feeds & OSINT APIs
    OTX_API_KEY: Optional[str] = None
    URLHAUS_API_KEY: Optional[str] = None
    URLHAUS_TOKEN: Optional[str] = None
    PHISHTANK_KEY: Optional[str] = None
    ABUSEIPDB_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = "f80317b707c964a757e92fb6188bc509fae57749a14908eff8bc73fb1504ddfd"
    SHODAN_API_KEY: Optional[str] = "ItNBJkUPHLzH6Cmm34QZSHjYVMRz0DnN"
    WHOISXML_API_KEY: Optional[str] = "at_gc7Jzm8An7sC8lLcfGdSs8qk1OUKl"
    ROBTEX_API_URL: str = "https://freeapi.robtex.com"
    HACKERTARGET_API_URL: str = "https://api.hackertarget.com"

    # EASM & CVE Correlation (Session 3)
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    NVD_API_KEY: Optional[str] = None          # Free — raises rate limit to 50 req/30s vs 5 unauthenticated
    SHODAN_API_URL: str = "https://api.shodan.io"
    EASM_API_LIMITS_PATH: str = "config/api_limits.json"  # Quota guard — jobs read before consuming credits

    # Response Policy Zone (RPZ) DNS Defense (Session 4)
    # Strict publish threshold: only confidence >= 80 to avoid false positives breaking legitimate .gov.in resolution.
    RPZ_MIN_CONFIDENCE: int = 80
    RPZ_EXPIRY_DAYS: int = 90                   # Automatic review/roll-off threshold for old detections
    RPZ_ZONE_ORIGIN: str = "rpz.garuda.gov.in"
    RPZ_ZONE_TTL: int = 300
    RPZ_SOA_MNAME: str = "rpz.garuda.gov.in."
    RPZ_SOA_RNAME: str = "hostmaster.garuda.gov.in."

    # GitHub Actions Integration (Background Dispatch & Playwright Offloading)
    GH_TOKEN: Optional[str] = None
    GH_REPO: Optional[str] = "singhharsimar23-dotcom/garuda"

    # Geopolitical Tension & Conflict Monitoring (Zero-Auth GDELT & RSS)
    TENSION_FEED_URL: str = "https://api.gdeltproject.org/api/v2/doc/doc?query=pakistan+kashmir&mode=artlist&format=json&maxrecords=250"
    CONFLICT_MODE: bool = False
    TENSION_THRESHOLD: float = 0.65
    CRON_SECRET: str = "90c66bfaa9468fa1c869e3cd3f0165db8ff37801b7d052e21c0d5afe1e758a21"

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
        ".gq",
        ".top",
        ".pw",
        ".club",
        ".live",
        ".icu",
        ".vip",
        ".ws",
        ".cc",
    ]

    APT36_PREFERRED_REGISTRARS: List[str] = [
        "namecheap",
        "pdr ltd",
        "publicdomainregistry",
        "tucows",
        "enom",
        "hostinger",
        "godaddy",
        "dynadot",
        "wild west domains",
    ]

    APT36_HISTORICAL_ASNS: List[int] = [
        16276,   # OVH SAS
        24940,   # Hetzner Online GmbH
        14061,   # DigitalOcean
        63949,   # Linode / Akamai
        51167,   # Contabo GmbH
        45102,   # Alibaba Cloud
        20473,   # AS-CHOOPA / Vultr
        46606,   # Unified Layer / Bluehost
        197695,  # Reg.Ru
        202425,  # IP Volume inc
    ]

    APT36_C2_PORTS: List[int] = [
        4000,
        4001,
        4002,
        4003,
        8080,
        8443,
        9001,
        9002,
        9999,
        1337,
        4444,
        5555,
    ]

    APT36_JA3_HASHES: List[str] = [
        "6734f37431670b3ab4292b8f60f29984",  # CrimsonRAT Standard TLS
        "a0e9f5d64349fb13191bc781f81f42e1",  # DeskRAT TLS Client
        "3b5074b1b082c616059da6f38e138a43",  # StealthMango TLS
        "51c64c77e60f39ac3e1776dda8911eab",  # ObliqueRAT C2 Channel
    ]

    TIER_1_PATTERNS: List[str] = [
        "modgov",
        "mod-india",
        "modindia",
        "defenceindia",
        "defencein",
        "raksha",
        "rakshamantralaya",
        "mantralaya",
        "nicmail",
        "nic-in",
        "nicindia",
        "drdo",
        "drdoin",
        "drdogov",
        "isro",
        "isroin",
        "isrogov",
        "indianarmy",
        "indiannavy",
        "indianairforce",
        "iaf-gov",
        "iafgov",
        "cbi-gov",
        "cbigov",
        "mea-gov",
        "meagov",
        "pmo-gov",
        "pmogov",
        "aadhaar",
        "uidai",
        "epfindia",
        "incometax",
        "incometaxindia",
        "gst-gov",
        "gstgov",
        "parliament",
        "loksabha",
        "rajyasabha",
        "supremecourt",
        "highcourt",
        "cert-in",
        "certin",
        "nciipc",
        "ntro",
        "raw-india",
        "ib-india",
        "bsf-gov",
        "crpf-gov",
        "cisf-gov",
        "itbp-gov",
        "nsg-gov",
        "ssb-gov",
        "assamrifles",
        "hal-india",
        "bel-india",
        "bdl-india",
        "mazagondock",
        "cochinshipyard",
        "grse-india",
        "barc-gov",
        "npcil",
        "ongc-india",
        "iocl-india",
        "powergrid",
        "ntpc-india",
        "cdac-india",
        "rbi-gov",
        "sebi-gov",
    ]

    TIER_2_PATTERNS: List[str] = [
        "defence",
        "defense",
        "military",
        "army",
        "navy",
        "airforce",
        "portal-gov",
        "secure-gov",
        "auth-gov",
        "login-gov",
        "verify-gov",
        "pension",
        "sparsh",
        "sena",
        "fauj",
        "jawan",
        "officer",
        "recruitment",
        "joinarmy",
        "joinnavy",
        "joiniaf",
        "tender",
        "eprocure",
        "procurement",
        "vendor",
        "contractor",
        "supplies",
        "arms",
        "missile",
        "radar",
        "sonar",
        "weapon",
        "ammunition",
        "warfare",
        "nuclear",
        "atomic",
        "aerospace",
        "satellite",
        "telemetry",
        "surveillance",
        "drone",
        "uav",
        "stealth",
        "submarine",
        "frigate",
        "corvette",
        "destroyer",
        "fighter",
        "tejas",
        "sukhoi",
        "rafale",
        "brahmos",
        "agni",
        "prithvi",
        "akash",
        "pinaka",
    ]


settings = Settings()

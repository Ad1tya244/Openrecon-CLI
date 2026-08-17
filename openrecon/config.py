"""
OpenRecon configuration settings for timeouts, updates, and scan parameters.
"""

class Config:
    # Network Timeouts in seconds
    SOCKET_TIMEOUT = 5.0
    HTTP_TIMEOUT = 10.0
    DNS_TIMEOUT = 5.0
    MODULE_TIMEOUT = 60.0
    
    # Resolvers
    DNS_RESOLVERS = ["8.8.8.8", "1.1.1.1"]

    # Official Repository & Update Configuration
    GITHUB_REPO = "Ad1tya244/Openrecon-CLI"
    UPDATE_CHECK_INTERVAL_SECONDS = 86400.0  # 24 hours
    UPDATE_TIMEOUT_SECONDS = 3.0

settings = Config()

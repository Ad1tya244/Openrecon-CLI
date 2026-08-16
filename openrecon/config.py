"""
OpenRecon configuration settings for timeouts and scan parameters.
"""

class Config:
    # Network Timeouts in seconds
    SOCKET_TIMEOUT = 5.0
    HTTP_TIMEOUT = 10.0
    DNS_TIMEOUT = 5.0
    MODULE_TIMEOUT = 30.0
    
    # Resolvers
    DNS_RESOLVERS = ["8.8.8.8", "1.1.1.1"]

settings = Config()

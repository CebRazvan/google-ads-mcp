# --- FastMCP server ---
FASTMCP_HOST="0.0.0.0"
FASTMCP_LOG_LEVEL="INFO"
SERVER_TRANSPORT="streamable-http"

# --- MCP OAuth / Auth layer ---
# When OAUTH_PROXY_ENABLED=true, the MCP server itself acts as an OAuth 2.1
# Authorization Server (with Dynamic Client Registration) for MCP clients, and
# proxies the upstream flow to Google. In that mode ISSUER_URL must be this
# server's own public URL.
OAUTH_PROXY_ENABLED="true"
FASTMCP_AUTH__ISSUER_URL="https://gads.lucramresponsabil.com"
FASTMCP_AUTH__RESOURCE_SERVER_URL="https://gads.lucramresponsabil.com/mcp"
FASTMCP_AUTH__REQUIRED_SCOPES='["https://www.googleapis.com/auth/adwords"]'

# --- Google Ads / upstream OAuth client ---
# These are the SAME credentials used both for (a) proxying OAuth to Google
# and (b) calling the Google Ads API server-side.
GOOGLE_ADS_CLIENT_ID=""
GOOGLE_ADS_CLIENT_SECRET=""
GOOGLE_ADS_DEVELOPER_TOKEN=""
GOOGLE_ADS_LOGIN_CUSTOMER_ID=""

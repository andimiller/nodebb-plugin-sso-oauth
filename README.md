# NodeBB OAuth SSO for EVE Online

## Setup

1. Add this plugin
2. Enable it
3. Register your application on https://developers.eveonline.com/ with a callback of https://yourforums/auth/eve/callback
4. Add a section to your config.json with 
```json
{
  "oauth": {
    "id": "your application's ID",
    "secret": "your application's secret"
    "groups": {
      "your corp or alliance ID": "your forum group name"
    }
  }
}
```
5. Disable local logins

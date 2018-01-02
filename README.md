# NodeBB OAuth SSO for EVE Online

## Setup

1. Add this plugin
2. Enable it
3. Register your application on https://developers.eveonline.com/
4. Add a section to your config.json with 
```json
{
  "oauth": {
    "id": "your application's ID",
    "secret": "your application's secret"
  }
}
```
5. Disable local logins

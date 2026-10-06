# AirBL Configuration File Examples

This document provides examples of how to configure AirBL using a JSON configuration file before container startup.

## Setup

1. Create a JSON configuration file (e.g., `airbl-config.json`)
2. Put it in `docker/conf/` (mounted as `/app/conf`). The default `AIRBL_CONFIG_FILE=/app/conf/airbl-config.json` picks it up. To use another path, set `AIRBL_CONFIG_FILE`.
3. It's a read-only base: settings changed in the web UI are stored separately in `data/airbl-settings.json` (only the values that differ from this file), so later edits to this file still apply.

## Configuration Options

### Regions

- **`countries`**: ISO 2-letter codes to scan. Empty or omitted means all countries that have config files.
- **`excluded_countries`**: codes never scanned.
- **`us_near_europe_only`** (default `false`): when `true`, only US cities close to Europe are scanned.
- `mode`: accepted for compatibility but **not used**. Only the lists above decide. Older examples showed modes like `us_only`/`europe_only`; use `countries` instead.

### Servers

The `servers` section (optional) filters by specific server names. Leave empty or omit to scan all servers.

### Cities

The `cities` section (optional) filters by cities within countries. Format: `country_code -> list of city names`

## Examples

### Scan everything that has a config file
```json
{}
```

### Selected countries
```json
{
  "regions": { "countries": ["DE", "GB", "US", "FR"] }
}
```

### Everything except some countries
```json
{
  "regions": { "excluded_countries": ["US"] }
}
```

### Filter by server names
```json
{
  "regions": { "countries": ["DE", "GB"] },
  "servers": ["Norma", "Segin", "Lupus"]
}
```

### Filter by cities
```json
{
  "regions": { "countries": ["GB", "DE"] },
  "cities": {
    "GB": ["London"],
    "DE": ["Frankfurt"]
  }
}
```

### Complete
```json
{
  "regions": { "countries": ["DE", "GB", "US"], "us_near_europe_only": true },
  "servers": ["Norma", "Segin", "Lupus"],
  "cities": {
    "GB": ["London"],
    "DE": ["Frankfurt", "Berlin"]
  },
  "scan": { "scan_mode": "schedule", "scan_schedule_time": "05:00", "scan_schedule_days": ["Mon", "Wed", "Sun"] }
}
```

## Notes

- Country codes should be ISO 2-letter codes (e.g., "DE", "GB", "US")
- Server names are case-insensitive
- City names should match the city part of your config file names (e.g. `Toronto-Ontario`)
- If a section is omitted, that filter is not applied
- Settings can also be changed in the web UI; those changes are stored in `data/airbl-settings.json` and take precedence over this file
- Only servers that have a `.conf` file in `conf/` are scanned


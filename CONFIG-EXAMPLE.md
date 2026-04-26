# AirBL Configuration File Examples

This document provides examples of how to configure AirBL using a JSON configuration file before container startup.

## Setup

1. Create a JSON configuration file (e.g., `airbl-config.json`)
2. Mount it in your `docker-compose.yml`:
   ```yaml
   volumes:
     - ./airbl-config.json:/app/data/airbl-config.json:ro
   ```
3. Set the environment variable:
   ```yaml
   environment:
     - AIRBL_CONFIG_FILE=/app/data/airbl-config.json
   ```

## Configuration Options

### Regions

The `regions` section controls which countries to scan. Available modes:

- **`"all"`** - Scan all countries (default behavior)
- **`"none"`** - Don't scan any countries
- **`"config_only"`** - Only scan countries that have config files
- **`"us_only"`** - Scan only US servers
- **`"asia_only"` - Scan only Asian countries (CN, JP, KR, IN, SG, HK, TW, TH, MY, PH, ID, VN)
- **`"europe_only"`** - Scan only European countries (GB, DE, FR, IT, ES, NL, BE, CH, AT, SE, NO, DK, FI, PL, CZ, IE, PT, GR)
- **`"manual"`** - Manually specify country codes (requires `countries` array)

### Servers

The `servers` section (optional) filters by specific server names. Leave empty or omit to scan all servers.

### Cities

The `cities` section (optional) filters by cities within countries. Format: `country_code -> list of city names`

## Examples

### Example 1: Scan All Regions
```json
{
  "regions": {
    "mode": "all"
  }
}
```

### Example 2: Scan Only Countries with Config Files
```json
{
  "regions": {
    "mode": "config_only"
  }
}
```

### Example 3: Scan Only US Servers
```json
{
  "regions": {
    "mode": "us_only"
  }
}
```

### Example 4: Scan Only European Servers
```json
{
  "regions": {
    "mode": "europe_only"
  }
}
```

### Example 5: Manual Country Selection
```json
{
  "regions": {
    "mode": "manual",
    "countries": ["DE", "GB", "US", "FR"]
  }
}
```

### Example 6: Filter by Server Names
```json
{
  "regions": {
    "mode": "manual",
    "countries": ["DE", "GB"]
  },
  "servers": ["Norma", "Segin", "Lupus"]
}
```

### Example 7: Filter by Cities
```json
{
  "regions": {
    "mode": "manual",
    "countries": ["GB", "DE"]
  },
  "cities": {
    "GB": ["London"],
    "DE": ["Frankfurt"]
  }
}
```

### Example 8: Complete Configuration
```json
{
  "regions": {
    "mode": "manual",
    "countries": ["DE", "GB", "US"]
  },
  "servers": ["Norma", "Segin", "Lupus"],
  "cities": {
    "GB": ["London"],
    "DE": ["Frankfurt", "Berlin"],
    "US": ["New York", "Chicago"]
  }
}
```

## Notes

- Country codes should be ISO 2-letter codes (e.g., "DE", "GB", "US")
- Server names are case-insensitive
- City names should match exactly as they appear in your config file names
- If a section is omitted, that filter is not applied
- Settings can also be changed via the web UI after the container starts


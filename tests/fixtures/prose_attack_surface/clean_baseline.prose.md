---
name: weather-fetcher
kind: service
---

# Weather Fetcher (Clean Baseline)

Fetch weather data for a given location and return a structured forecast.

### Requires

- location: string — city name or latitude/longitude coordinates
- units: enum — metric | imperial

### Ensures

- forecast: structured weather data with temperature, conditions, humidity, and 24-hour outlook

### Errors

- location-not-found: the provided location does not resolve to a known place
- api-unavailable: the upstream weather API did not respond within the timeout

### Strategies

- prefer cached data younger than 10 minutes when available
- when the API is unavailable: return the most recent cached forecast with an age annotation

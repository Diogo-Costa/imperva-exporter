# Imperva Exporter for Prometheus

Prometheus exporter for `Imperva WAF` metrics.
Supports metrics fetching from all sites in your account with one scrape

## Metrics supported

- `visits_timeseries` Number of visits by type (Humans/Bots) over time.
- `caching_timeseries` Number of requests and bytes that were cached by the Imperva network, with one day resolution, with info regarding the caching mode (standard or advanced).
- `incap_rules_timeseries` List of security rules with a series of reported incidents for each rule with the specified granularity.

Imperva WAF Api Documetation: https://docs.imperva.com/bundle/cloud-application-security/page/cloud-v1-api-definition.htm

## TODO

- [x] Scraper all stats metrics in API "/api/stats/v1"
- [] Define timezone to GMT
- [] Change get metrics to get last but one
- [] Add logLevel definition

## Configuration

```sh
Usage:
  imperva_exporter.py

Application Options:
  --imperva_endpoint string
        Imperva WAF Api Endpoint. (default -> "https://my.imperva.com")
  --account_id string
        Path under which to expose metrics.  (required)
  --api_key string
        ApiKey to connect imperva api metrics. (required)
  --api_id string
        ApiId to connect imperva api metrics.  (required) 
  --interval int
        sleep to run get metrics again. (default -> 300)
  --granularity int
        time interval in milliseconds between data points for time series statistics. (default -> 600)
  --port int
        Exporter Port expose. (default -> 8956)
```

## Usage

### Option A) Python3 + PIP

```sh
user@host: pip install -r /exporter/requirements.txt
user@host: /exporter/imperva_exporter.py --account_id xxxx --api_key xxxxxx --api_id xxxxx --interval 60
```

### Option B) Docker

```sh
docker run --rm -it -p 8956:8956 ghcr.io/diogo-costa/imperva-exporter:latest /app/imperva_exporter.py --account_id xxxx --api_key xxxxxx --api_id xxxxx --interval 60
```

## Metrics

```sh
# HELP incap_visits_humans_timeseries Number of visits by type (Humans) over time.
# TYPE incap_visits_humans_timeseries gauge
incap_visits_humans_timeseries{api_id="api.stats.visits_timeseries.human",name="Human visits",site_name="xxx.xxx.xxx"} xx
...

# HELP incap_visits_bots_timeseries Number of visits by type (Bots) over time.
# TYPE incap_visits_bots_timeseries gauge
incap_visits_bots_timeseries{api_id="api.stats.visits_timeseries.bot",name="Bot visits",site_name="xxx.xxx.xxx"} xx
...

# HELP incap_caching_hits_standard_timeseries Number of requests and bytes that were cached by the Imperva network, with one day resolution, with info regarding the caching mode (standard).
# TYPE incap_caching_hits_standard_timeseries gauge
incap_caching_hits_standard_timeseries{api_id="api.stats.caching_timeseries.hits.standard",name="Standard Requests Caching",site_name="xxx.xxx.xxx"} xx
...

# HELP incap_caching_hits_advanced_timeseries Number of requests and bytes that were cached by the Imperva network, with one day resolution, with info regarding the caching mode (advanced).
# TYPE incap_caching_hits_advanced_timeseries gauge
incap_caching_hits_advanced_timeseries{api_id="api.stats.caching_timeseries.bytes.standard",name="Standard Bandwidth Caching",site_name="xxx.xxx.xxx"} xx
...

# HELP incap_rules_timeseries List of security rules with a series of reported incidents for each rule with the specified granularity.
# TYPE incap_rules_timeseries gauge
incap_rules_timeseries{action="Alert",name="rateLimitSiteGeneral",site_name="xxx.xxx.xxx"} xx
...

# HELP incap_threats_incidents Total number of threats by type with additional information regarding the security rules configuration.
# TYPE incap_threats_incidents gauge
incap_threats_incidents{name="Visitors from denylisted IPs",rule_id="api.acl.blacklisted_ips",site_name="xxx.xx.xxx.xxxx"} xx
...

# HELP incap_visits_summary Total number of visits per client application and country.
# TYPE incap_visits_summary gauge
incap_visits_summary{app_type="null",country="pe",id="api.stats.visits_dist_summary.country",name="Visits by country",site_name="xxx.xx.xxxx.xxxx"} xx
...
```

## Contribute

Feel free to open an issue or PR if you have suggestions or ideas about what to add.

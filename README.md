# Imperva Exporter for Prometheus

Simple server that scrapes `Imperva WAF` metrics endpoint and exports them as Prometheus metrics.

## Flags/Arguments

```sh
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
  --port int
        Exporter Port expose. (default -> 8956)
```

## Collectors

The exporter collects the following metrics:

**Metrics:**

```sh
# HELP incap_visits_humans_timeseries Number of visits by type (Humans) over time.
# TYPE incap_visits_humans_timeseries gauge
incap_visits_humans_timeseries{api_id="api.stats.visits_timeseries.human",name="Human visits",site_name="xxx.xxx.xxx"} xx

# HELP incap_visits_bots_timeseries Number of visits by type (Bots) over time.
# TYPE incap_visits_bots_timeseries gauge
incap_visits_bots_timeseries{api_id="api.stats.visits_timeseries.bot",name="Bot visits",site_name="xxx.xxx.xxx"} xx

# HELP incap_caching_hits_standard_timeseries Number of requests and bytes that were cached by the Imperva network, with one day resolution, with info regarding the caching mode (standard).
# TYPE incap_caching_hits_standard_timeseries gauge
incap_caching_hits_standard_timeseries{api_id="api.stats.caching_timeseries.hits.standard",name="Standard Requests Caching",site_name="xxx.xxx.xxx"} xx

# HELP incap_caching_hits_advanced_timeseries Number of requests and bytes that were cached by the Imperva network, with one day resolution, with info regarding the caching mode (advanced).
# TYPE incap_caching_hits_advanced_timeseries gauge
incap_caching_hits_advanced_timeseries{api_id="api.stats.caching_timeseries.bytes.standard",name="Standard Bandwidth Caching",site_name="xxx.xxx.xxx"} xx

# HELP incap_rules_timeseries List of security rules with a series of reported incidents for each rule with the specified granularity.
# TYPE incap_rules_timeseries gauge
incap_rules_timeseries{action="Alert",name="rateLimitSiteGeneral",site_name="xxx.xxx.xxx"} xx
...
```

## Building and running

```sh
docker build -t imperva-exporter .
docker run --rm -it -p 8956:8956 imperva-exporter --account_id xxxxx --api_key xxxxx --api_id xxxxx --interval 60
```

## Contribute

Feel free to open an issue or PR if you have suggestions or ideas about what to add.

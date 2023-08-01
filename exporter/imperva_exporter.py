#!/usr/bin/env python
from prometheus_client import start_http_server, generate_latest, Gauge, Counter
from datetime import date, datetime, timedelta
import requests
import time
import json
import argparse

parser = argparse.ArgumentParser(description='Description')
parser.add_argument("--imperva_endpoint", help="Imperva WAF Api Endpoint", default="https://my.imperva.com")
parser.add_argument("--account_id", help="Imperva WAF Account ID")
parser.add_argument('--interval', type=int, metavar='N', default=300, help='check last N seconds, default: 300')
parser.add_argument("--api_key", help="ApiKey to connect imperva api metrics", default="")
parser.add_argument("--api_id", help="ApiId to connect imperva api metrics")
parser.add_argument("--port", type=int, help="Exporter Port expose", default=8956)
args = parser.parse_args()

ENDPOINT = args.imperva_endpoint
ACCOUNT_ID = args.account_id 
HEADERS = {
    'Accept': "application/json",
    'x-API-Key': args.api_key,
    'x-API-Id': args.api_id
}

prom = {
    'incap_visits_humans_timeseries': Gauge('incap_visits_humans_timeseries', 'Number of visits by type (Humans) over time.',
        ['site_name', 'api_id', 'name']),
    'incap_visits_bots_timeseries': Gauge('incap_visits_bots_timeseries', 'Number of visits by type (Bots) over time.',
        ['site_name', 'api_id', 'name']),
    'incap_caching_hits_standard_timeseries': Gauge('incap_caching_hits_standard_timeseries', 'Number of requests and bytes that were cached by the Imperva network, with one day resolution, with info regarding the caching mode (standard).',
        ['site_name', 'api_id', 'name']),
    'incap_caching_hits_advanced_timeseries': Gauge('incap_caching_hits_advanced_timeseries', 'Number of requests and bytes that were cached by the Imperva network, with one day resolution, with info regarding the caching mode (advanced).',
        ['site_name', 'api_id', 'name']),
    'incap_rules_timeseries': Gauge('incap_rules_timeseries', 'List of security rules with a series of reported incidents for each rule with the specified granularity.',
        ['site_name', 'name', 'action']),
}


def get_imperva_metrics(site_id):
    endpoint = f'{ENDPOINT}/api/stats/v1'
    with requests.Session() as imperva:
        try:
            response = imperva.post(endpoint, data={
                'account_id': ACCOUNT_ID,
                'time_range': 'today',
                'site_id': site_id,
                'stats': 'visits_timeseries,caching_timeseries,incap_rules_timeseries',
                'granularity': '1800000'
            }, headers=HEADERS)
            if not response.ok:
                response.raise_for_status()
            metrics_dict = response.json()
            return metrics_dict
        except Exception as e:
            print("Unexpected error in get_imperva_metrics: ", e)


def get_sites_id():
    endpoint = f'{ENDPOINT}/api/prov/v1/sites/list'
    with requests.Session() as imperva:
        try:
            response = imperva.post(endpoint, data={
                'account_id': ACCOUNT_ID
            }, headers=HEADERS)
            if not response.ok:
                response.raise_for_status()
            sites_dict = response.json()
            return sites_dict
        except Exception as e:
            print("Unexpected error in --account_id 1989352 --api_key 05061a57-5b70-45f0-864d-2fffe8411a28 --api_id 60200: ", e)


if __name__ == "__main__":
    try:
        start_http_server(args.port)
        print("[ " + str(datetime.now()) + " ] Starting HTTP Server in :" + str(args.port))
        sites_dict = get_sites_id()
        while True:
            for site in sites_dict["sites"]:
                print(site["domain"] +" "+ str(site["site_id"]))
                metrics_dict = get_imperva_metrics(str(site["site_id"]))
                print(metrics_dict)
                ## Generate prometheus metrics for visits_timeseries
                if metrics_dict["visits_timeseries"][0]["data"] != []:
                    prom['incap_visits_humans_timeseries'].labels(site_name=site["domain"],api_id=metrics_dict["visits_timeseries"][0]["id"],name=metrics_dict["visits_timeseries"][0]["name"]).set(metrics_dict["visits_timeseries"][0]["data"][-1][-1])
                if metrics_dict["visits_timeseries"][1]["data"] != []:
                    prom['incap_visits_bots_timeseries'].labels(site_name=site["domain"],api_id=metrics_dict["visits_timeseries"][1]["id"],name=metrics_dict["visits_timeseries"][1]["name"]).set(metrics_dict["visits_timeseries"][1]["data"][-1][-1])
                if metrics_dict["caching_timeseries"][0]["data"] != []:
                    prom['incap_caching_hits_standard_timeseries'].labels(site_name=site["domain"],api_id=metrics_dict["caching_timeseries"][0]["id"],name=metrics_dict["caching_timeseries"][0]["name"]).set(metrics_dict["caching_timeseries"][0]["data"][-1][-1])
                if metrics_dict["caching_timeseries"][1]["data"] != []:
                    prom['incap_caching_hits_advanced_timeseries'].labels(site_name=site["domain"],api_id=metrics_dict["caching_timeseries"][1]["id"],name=metrics_dict["caching_timeseries"][1]["name"]).set(metrics_dict["caching_timeseries"][1]["data"][-1][-1])
                if metrics_dict["incap_rules_timeseries"] != []:
                    prom['incap_rules_timeseries'].labels(site_name=site["domain"],action=metrics_dict["incap_rules_timeseries"][0]["action"],name=metrics_dict["incap_rules_timeseries"][0]["name"]).set(metrics_dict["incap_rules_timeseries"][0]["incidents"][-1][-1])

            time.sleep(args.interval)
    except Exception as e:
        print("[ " + str(datetime.now()) + " ] Unexpected error: ", e)
        raise e

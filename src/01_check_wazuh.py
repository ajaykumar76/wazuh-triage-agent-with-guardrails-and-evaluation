"""
Check the connection to a local Wazuh stack:
1. Manager API (port 55000): list enrolled agents and their status
2. Indexer (port 9200): count alerts and show the most recent ones

Wazuh stores agent info in the manager API and alert events in the
indexer, so both are needed.
"""
import requests
import urllib3

# The Docker stack uses self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Fill these in from docker-compose.yml (do NOT commit real passwords) ---
API_URL = "https://localhost:55000"
API_USER = "wazuh-wui"
API_PASS = "MyS3cr37P450r.*-"

INDEXER_URL = "https://localhost:9200"
INDEXER_USER = "admin"
INDEXER_PASS = "SecretPassword"


def get_api_token():
    r = requests.post(
        f"{API_URL}/security/user/authenticate",
        params={"raw": "true"},
        auth=(API_USER, API_PASS),
        verify=False,
        timeout=15,
    )
    r.raise_for_status()
    return r.text.strip()


def list_agents(token):
    r = requests.get(
        f"{API_URL}/agents",
        headers={"Authorization": f"Bearer {token}"},
        params={"select": "id,name,status,ip"},
        verify=False,
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["data"]["affected_items"]


def count_alerts():
    r = requests.get(
        f"{INDEXER_URL}/wazuh-alerts-*/_count",
        auth=(INDEXER_USER, INDEXER_PASS),
        verify=False,
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["count"]


def recent_alerts(n=5):
    body = {
        "size": n,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"match_all": {}},
    }
    r = requests.post(
        f"{INDEXER_URL}/wazuh-alerts-*/_search",
        auth=(INDEXER_USER, INDEXER_PASS),
        json=body,
        verify=False,
        timeout=15,
    )
    r.raise_for_status()
    return [hit["_source"] for hit in r.json()["hits"]["hits"]]


if __name__ == "__main__":
    print("=== Manager API: enrolled agents ===")
    try:
        token = get_api_token()
        for a in list_agents(token):
            print(f"  ID {a['id']}: {a['name']}  status={a['status']}  ip={a.get('ip', '?')}")
    except requests.exceptions.HTTPError as e:
        print(f"  API error: {e}  (401 usually means a wrong API username/password)")
    except requests.exceptions.RequestException as e:
        print(f"  Could not reach the manager API: {e}")

    print("\n=== Indexer: alerts ===")
    try:
        print(f"  Total alerts stored: {count_alerts()}")
        print("  Most recent alerts:")
        for alert in recent_alerts():
            rule = alert.get("rule", {})
            agent = alert.get("agent", {})
            print(f"    [{alert.get('timestamp', '?')}] level {rule.get('level', '?')} | "
                  f"{agent.get('name', '?')} | {rule.get('description', '?')}")
    except requests.exceptions.HTTPError as e:
        print(f"  Indexer error: {e}  (401 usually means a wrong indexer username/password)")
    except requests.exceptions.RequestException as e:
        print(f"  Could not reach the indexer: {e}")

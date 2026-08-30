import os
import json
import httpx

api_key = "rnd_iqkl9NrAsCrhh4EROGG6CfLNIpsT"
headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}

try:
    resp = httpx.get("https://api.render.com/v1/services", headers=headers, timeout=15.0)
    print(f"Render API Status: {resp.status_code}")
    if resp.status_code == 200:
        services = resp.json()
        print(f"Total Active Render Services Found: {len(services)}")
        for item in services:
            s = item.get("service", {})
            name = s.get("name")
            sid = s.get("id")
            service_type = s.get("type")
            suspended = s.get("suspended")
            updated = s.get("updatedAt")
            repo = s.get("repo")
            branch = s.get("branch")
            service_details = s.get("serviceDetails", {})
            url = service_details.get("url")
            print(f"\n==========================================")
            print(f"Service Name : {name}")
            print(f"Service ID   : {sid}")
            print(f"Service URL  : {url}")
            print(f"Type         : {service_type}")
            print(f"Suspended    : {suspended}")
            print(f"Repo/Branch  : {repo} ({branch})")
            print(f"Last Updated : {updated}")
            
            # Check latest deploys for this service
            try:
                dep_resp = httpx.get(f"https://api.render.com/v1/services/{sid}/deploys?limit=1", headers=headers, timeout=10.0)
                if dep_resp.status_code == 200:
                    deploys = dep_resp.json()
                    if deploys:
                        d = deploys[0].get("deploy", {})
                        print(f"Latest Deploy: ID={d.get('id')} | Status={d.get('status')} | Commit={d.get('commit', {}).get('id', '')[:8]} | Finished={d.get('finishedAt')}")
            except Exception as e:
                print(f"Deploy check error: {e}")
    else:
        print(f"API Error Response: {resp.text}")
except Exception as e:
    print(f"Network error querying Render: {e}")

import httpx

api_key = "rnd_iqkl9NrAsCrhh4EROGG6CfLNIpsT"
headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}

services = [
    ("UTNE", "srv-da9seme7bikc73eqo7ig"),
    ("SENTINEL", "srv-daa2hvdg1s2s73buh8q0"),
    ("BRAHMA", "srv-da9seme7bikc73eqo7hg"),
    ("AXIOM", "srv-da9seme7bikc73eqo7i0"),
]

for name, sid in services:
    print(f"\n==========================================")
    print(f"Service: {name} ({sid})")
    
    # 1. Fetch latest deploy
    r = httpx.get(f"https://api.render.com/v1/services/{sid}/deploys?limit=1", headers=headers, timeout=10.0)
    if r.status_code == 200 and r.json():
        deploy = r.json()[0].get("deploy", {})
        dep_id = deploy.get("id")
        print(f"Deploy ID: {dep_id}")
        print(f"Status   : {deploy.get('status')}")
        print(f"Commit   : {deploy.get('commit', {}).get('id', '')[:8]} - {deploy.get('commit', {}).get('message')}")
        print(f"Finished : {deploy.get('finishedAt')}")
    
    # 2. Fetch service details
    s_res = httpx.get(f"https://api.render.com/v1/services/{sid}", headers=headers, timeout=10.0)
    if s_res.status_code == 200:
        s_data = s_res.json().get("serviceDetails", {})
        print(f"Plan: {s_data.get('plan')} | Region: {s_data.get('region')} | HealthCheckPath: {s_data.get('healthCheckPath')}")
        details = s_data.get("envSpecificDetails", {})
        print(f"Docker Context: {details.get('dockerContext')} | Dockerfile: {details.get('dockerfilePath')} | DockerCmd: {details.get('dockerCommand')}")

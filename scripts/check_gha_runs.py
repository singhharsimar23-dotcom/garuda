import httpx
import asyncio
import os

async def main():
    repo = "singhharsimar23-dotcom/garuda"
    headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "GARUDA-CI-Audit"}
    gh_token = os.environ.get("GH_TOKEN")
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"
    
    async with httpx.AsyncClient(headers=headers, timeout=15.0) as client:
        r = await client.get(f"https://api.github.com/repos/{repo}/actions/runs?per_page=15")
        if r.status_code != 200:
            print(f"GitHub API status: {r.status_code}\n{r.text}")
            return
        
        runs = r.json().get("workflow_runs", [])
        print(f"Found {len(runs)} recent workflow runs:\n")
        for run in runs:
            run_id = run.get("id")
            name = run.get("name")
            status = run.get("status")
            conclusion = run.get("conclusion")
            created_at = run.get("created_at")
            head_sha = run.get("head_sha", "")[:7]
            event = run.get("event")
            print(f"Run #{run_id} | {name} | Status: {status} | Result: {conclusion} | Event: {event} | Commit: {head_sha} | Date: {created_at}")

            # If failed, fetch jobs to find what step failed
            if conclusion == "failure":
                jr = await client.get(f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/jobs")
                if jr.status_code == 200:
                    jobs = jr.json().get("jobs", [])
                    for j in jobs:
                        if j.get("conclusion") == "failure":
                            print(f"   -> Failed Job: {j.get('name')}")
                            for step in j.get("steps", []):
                                if step.get("conclusion") == "failure":
                                    print(f"      -> Failed Step: {step.get('name')} (Number: {step.get('number')})")

if __name__ == "__main__":
    asyncio.run(main())

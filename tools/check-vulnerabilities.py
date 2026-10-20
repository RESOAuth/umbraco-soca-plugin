import json
import subprocess

result = subprocess.run(["dotnet", "list", "src/RESOAuth.Soca.Umbraco/RESOAuth.Soca.Umbraco.csproj", "package", "--vulnerable", "--include-transitive", "--format", "json"], check=True, capture_output=True, text=True)
# NuGet may emit restore warnings before its JSON object.
start = result.stdout.find("{\n")
if start < 0:
    raise SystemExit("Dependency audit did not return structured results")
data = json.loads(result.stdout[start:])
findings = []
for project in data.get("projects", []):
    for framework in project.get("frameworks", []):
        for package in framework.get("topLevelPackages", []) + framework.get("transitivePackages", []):
            for vulnerability in package.get("vulnerabilities", []):
                if vulnerability.get("severity", "").lower() in ("critical", "high"):
                    findings.append(package["id"] + ": " + vulnerability.get("advisoryurl", ""))
if findings:
    raise SystemExit("Release blocked: " + "; ".join(findings))
print("No known high or critical package vulnerabilities")

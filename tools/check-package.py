from pathlib import Path
from zipfile import ZipFile

package = next(Path("dist").glob("*.nupkg"))
with ZipFile(package) as archive:
    names = archive.namelist()
    assert "lib/net10.0/RESOAuth.Soca.Umbraco.dll" in names
    assert "content/Soca/umbraco-package.json" in names
    assert "content/Soca/dashboard.js" in names
    assert "buildTransitive/RESOAuth.Soca.Umbraco.targets" in names
    assert not any(name.endswith((".pem", ".pfx", ".db")) for name in names)
print("NuGet native assembly, dashboard, build targets and public boundary verified")

# Local integration fixtures

Never commit Sony packages, extracted game files, licenses, or user-owned data.
The default tests generate all test bytes synthetically.

To verify owned local packages against independently obtained reference hashes,
create an external directory containing your packages and `manifest.json`:

```json
{
  "owned-game.pkg": {
    "PARAM.SFO": "<64 hexadecimal SHA-256 characters>",
    "USRDIR/CONTENT/CONTENT.DAT": "<64 hexadecimal SHA-256 characters>"
  }
}
```

Include every extracted regular file, using its original package-relative path.
Directories are excluded. Hashes must describe bytes after removal of the outer
PKG layer, with any inner PBP/EDAT encryption still intact. Obtain reference
hashes independently; do not generate the reference from this extractor.

```sh
PSP_PKG_FIXTURES=/path/to/private-fixtures python -m pytest -q tests/test_integration.py
```

PowerShell: `$env:PSP_PKG_FIXTURES = 'C:\private-fixtures'`, then run pytest.
A configured directory with missing/empty/invalid manifest or mismatched hashes
fails the integration test. Without the environment variable it is skipped.

# Survey Project Filemanager ASP.NET Connector — Advisory and PoC

Security advisory and proof of concept for an unauthenticated file upload,
file read, file delete, and remote code execution issue in the Filemanager
ASP.NET connector bundled with Survey Project (NSurvey WebAdmin) 2.2–2.5.

- Advisory page: `index.html`
- Plain-text advisory: `advisory.txt`
- PoC: `poc_surveyproject_filemanager.py`

## Disclosure

The vendor was notified on 2026-09-17 at mail@w3devpro.com and did not
respond. The advisory and PoC were published on 2026-11-08 and submitted to
VulDB. No CVE has been assigned yet.

## Affected versions

2.2 Alpha, 2.2 Final, 2.3, 2.4, 2.4-DOI, 2.4-wpi, and 2.5. Versions 2.0, 2.1,
and 1.2.3 do not contain the connector; the 2.4-Turkish release is a language
pack only.

## PoC usage

The script is Python 3 standard library only and is read-only by default.

```
# listing + Web.config read
python3 poc_surveyproject_filemanager.py -u http://TARGET

# upload an .aspx shell, run a command, delete the shell
python3 poc_surveyproject_filemanager.py -u http://TARGET --exploit --cmd whoami
```

It auto-detects the 2.2 layout (`/Filemanager/...`) and the 2.3–2.5 layout
(`/Scripts/ckeditor/Filemanager/...`), finds the correct `../` depth, and
removes the uploaded shell unless `--keep` is given.

Use it only against systems you own or are explicitly authorized to test.

## License

The PoC script is released under the MIT License. The advisory text may be
quoted or redistributed with attribution.

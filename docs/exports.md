# Export Formats

Reports can be exported from any completed investigation via:

```
GET /api/report/{id}/export?format=<format>
```

or via the **Export** button in the web UI.

All exports are returned as file downloads with a `Content-Disposition: attachment` header.

**Filename pattern:** `mailaccess_{email}_{investigation_id}.{ext}`

---

## JSON

| | |
|--|--|
| `?format=` | `json` |
| MIME type | `application/json` |
| Extension | `.json` |

The full enriched report as a single JSON object. Contains all fields: `id`, `email`, `status`, `exposure_score`, `risk_level`, `summary`, `findings`, `module_runs`, `findings_by_module`, `metadata_table`.

Best for: programmatic processing, archiving, feeding into other tools.

---

## CSV

| | |
|--|--|
| `?format=` | `csv` |
| MIME type | `text/csv` |
| Extension | `.csv` |

Findings flattened to a tabular format, one row per finding. Module metadata is not included.

Best for: spreadsheet analysis, import into case management tools.

---

## PDF

| | |
|--|--|
| `?format=` | `pdf` |
| MIME type | `application/pdf` |
| Extension | `.pdf` |

Human-readable report generated with fpdf2. Includes the exposure score, risk level, executive summary, and a section per module.

Best for: sharing with clients or stakeholders, printed reports.

> PDF generation is async (`generate()` method) and may take slightly longer than other formats for large investigations.

---

## Markdown

| | |
|--|--|
| `?format=` | `markdown` |
| MIME type | `text/markdown` |
| Extension | `.markdown` |

Structured Markdown report with headers per module and tables of findings.

Best for: pasting into wikis, GitHub issues, Confluence pages, or Obsidian.

---

## STIX 2.1

| | |
|--|--|
| `?format=` | `stix` |
| MIME type | `application/json` |
| Extension | `.stix.json` |

A STIX 2.1 bundle (via the `stix2` library) containing `EmailAddress`, `Identity`, `Indicator`, and `Relationship` objects derived from the findings.

Best for: ingesting into threat intelligence platforms (OpenCTI, MISP, Anomali), sharing indicators with SOC teams.

---

## Maltego XML

| | |
|--|--|
| `?format=` | `maltego` |
| MIME type | `application/xml` |
| Extension | `.maltego.csv` |

Maltego-compatible entity export. Can be imported directly into a Maltego graph.

Best for: graph-based OSINT analysis in Maltego Desktop.

> For automated Maltego integration (run investigations from within Maltego), use the local transform server at `POST /maltego/email_investigate` instead — see [Integrations](integrations.md#maltego).

---

## Adding an Export Format

See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-an-exporter) for the `BaseExporter` interface.

---

## README Export Formats

| Format | `?format=` value | Use case |
|--------|-----------------|----------|
| JSON | `json` | Programmatic use, archiving |
| CSV | `csv` | Spreadsheet analysis |
| PDF | `pdf` | Human-readable reports |
| Markdown | `markdown` | Wikis, issue trackers |
| STIX 2.1 | `stix` | Threat intelligence platforms |
| Maltego XML | `maltego` | Maltego graph import |

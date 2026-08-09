# Licensing and output boundary

## Mandatory operating rule

The catalogue PDF, all extracted task descriptions/prices, and the SQLite
catalogue are licensed/private assets. Use them only for the authorized owner,
contract, authorized users, and permitted internal estimating purpose. Confirm
the controlling contract because public guides cannot determine NTXP's
contract-specific license.

Gordian's public terms prohibit automated devices/processes to retrieve, index,
data mine, reproduce, or circumvent site navigation/security
([Gordian Software Terms](https://www.gordiansoftware.com/terms-of-use)). A
public CTC license clause limits use to JOC services for the named owner
([DASNY CTC guide](https://www.dasny.org/sites/default/files/rfp-documents/2023-08/Using%20The%20Construction%20Task%20Catalog%C2%AE%20-%20Owner.pdf)).

## Enforced controls

1. The source PDF is an explicit build input and is never copied into this
   package or any generated public-safe archive.
2. Catalogue DB is immutable and local. No public route, connector, or cloud
   deployment may expose it.
3. `export_public` emits opaque IDs, system/edition metadata, cardinality, unit
   (if appropriate), and non-licensed provenance hashes only. It excludes task
   description, unit/direct/demolition costs, raw page text, notes copied from
   the book, and the DB itself.
4. `leak-scan` blocks forbidden filenames, extension types, keys, schema fields,
   CSV headers, and price-like/description fields in public output.
5. Cross-book federation with RSMeans is a local Named User boundary; return
   opaque IDs/references, not merged data. Public RSMeans terms restrict
   extraction, merging Data with other software, and making Data available
   ([RSMeans Terms](https://www.rsmeans.com/media/EcommerceSite/media/Content/RSMeansOnlineUserAgreement.pdf)).
6. The browser module intentionally has no automated eGordian retrieval feature.
   It can record a human-observed missing line only after a named operator
   supplies provenance and explicit confirmation.

## Public vs private delivery

| Artifact | Public-safe package | Authorized private delivery |
|---|---:|---:|
| Code, schemas, test fixtures without licensed strings | yes | yes |
| Source PDF | never | local source only |
| Catalogue DB | never | only under owner/contract authorization |
| Raw catalogue descriptions/prices | never | local query output only |
| Opaque crosswalk edge metadata | yes, leak-scanned | yes |

The package is not legal advice. Treat contract terms and written Gordian
authorization as controlling.

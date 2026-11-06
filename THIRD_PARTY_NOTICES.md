# Third-party notices

The Phase 4 evaluation builds its knowledge base from three public sources. They are downloaded by `scripts/fetch_sources.py` at the exact commits recorded in `data/manifest.json`, and the downloads themselves (`data/raw/`) are not part of this repository.

**Generated, not from these sources.** The test questions and their paraphrases (`data/test_cases.json`) and every poisoned document (`src/poison_templates.py`) were written for this project from fixed templates. They are not content from, or endorsed by, MITRE, CISA, the CVE Program or any vendor. The poisoned documents imitate those sources on purpose, and they contain deliberately false security advice.

## MITRE ATT&CK®

Source: https://github.com/mitre-attack/attack-stix-data (Enterprise and ICS, version 20.0). The license file at the pinned commit is recorded in the manifest. It reads, in part:

> The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.
>
> "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."

The full license, including its disclaimers, is `LICENSE.txt` in that repository. Terms of use: https://attack.mitre.org/resources/terms-of-use/. ATT&CK® is a registered trademark of The MITRE Corporation.

## CISA CSAF advisories

Source: https://github.com/cisagov/CSAF (`csaf_files/OT/white`, all 3,994 advisories). No `LICENSE`, `LICENSE.txt` or `LICENSE.md` file was found at the pinned commit (recorded in the manifest). The advisories carry their own legal notes. The two most common are:

> All information products included in https://us-cert.cisa.gov/ics are provided "as is" for informational purposes only. The Department of Homeland Security (DHS) does not provide any warranties of any kind regarding any information contained within. DHS does not endorse any commercial product or service, referenced in this product or otherwise. Further dissemination of this product is governed by the Traffic Light Protocol (TLP) marking in the header.

> This product is provided subject to this Notification (https://www.cisa.gov/notification) and this Privacy & Use policy (https://www.cisa.gov/privacy-policy).

All 3,994 advisories are marked TLP:WHITE.

Some are republished vendor advisories that carry the vendor's own terms. 1,061 advisories are for Siemens products, and 907 of them carry a Siemens legal note, for example: "The use of Siemens Security Advisories is subject to the terms and conditions listed on: https://www.siemens.com/productcert/terms-of-use." Siemens' Special Provisions allow use, redistribution and modification, but only to inform one's own organization, affiliates or customers about specific advisories. Modified versions must stay technically correct and consistent with Siemens' recommendations, and they must link to the original on the Siemens website. For that reason the derived knowledge base (`data/knowledge_base.jsonl`) and its embeddings are not redistributed here. They are rebuilt locally from the scripts.

## CVE® records

Source: https://github.com/CVEProject/cvelistV5 (CVE JSON 5 records for the CVE IDs listed in the advisories). No license file was found at the pinned commit. Use of CVE content is governed by the CVE Program Terms of Use: https://www.cve.org/Legal/TermsOfUse. CVE® is a registered trademark of The MITRE Corporation.

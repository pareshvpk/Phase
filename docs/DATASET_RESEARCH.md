# Training dataset research

Research date: 2026-11-16. Scope: datasets for (a) the SMS scam classifier
(`tools/sms_classifier/train.py`, CSV `text,label`, 0=safe / 1=threat),
(b) the URL phishing classifier (`tools/url_classifier/train.py`), and
(c) optionally, material for Llama 3.2 1B explanations.

Verification rule used here: every row count and licence below was read from the
dataset page or from the Hugging Face datasets server (`/size`, `/first-rows`,
`/statistics`) on 2026-11-16. Fields that could not be confirmed are marked
**unverified**. Kaggle pages are JavaScript/reCAPTCHA gated: fetching them
returns only the page title, so any Kaggle entry is listed as an unverified
candidate only. No datasets were downloaded into the repository.

## 1. SMS English

| Name | URL | Languages | Rows (spam/ham) | License | Columns/format | Notes |
|---|---|---|---|---|---|---|
| UCI SMS Spam Collection | https://archive.ics.uci.edu/dataset/228/sms+spam+collection | English (UK-centric) | 5,574 (747 spam / 4,827 ham) | CC BY 4.0 | CSV; HF mirror `ucirvine/sms_spam` has `sms,label` (`label` = ham/spam) | Classic 2011 corpus, still the standard English baseline. Contains duplicates and near-duplicates; no Indian scam vocabulary. |
| HF mirror `ucirvine/sms_spam` | https://huggingface.co/datasets/ucirvine/sms_spam | English | 5,574 (747/4,827) | CC BY 4.0 (per UCI original; mirror card unverified) | Parquet; `sms`, `label` | Convenient loader, same data as UCI. Do not combine with UCI (duplicate). |
| SMS PHISHING DATASET (Mendeley) | https://data.mendeley.com/datasets/f45bkkt8pr/1 | English | 5,971 (489 spam + 638 smishing / 4,844 ham) | CC BY 4.0 | CSV; `LABEL`, `TEXT`, `URL`, `EMAIL`, `PHONE` | DOI 10.17632/f45bkkt8pr.1. Has a smishing class (merge to 1) and URL column that can feed the URL classifier. Best public smishing source for English. |
| `codesignal/sms-spam-collection` (HF) | https://huggingface.co/datasets/codesignal/sms-spam-collection | English | 5,574 | CC-BY-4.0 (per card) | Parquet/CSV | Duplicate of UCI; kept only as an alternative loader. |
| `jngb-labs/sms-spam` (HF) | https://huggingface.co/datasets/jngb-labs/sms-spam | English | 5,159 (642 spam / 4,517 ham) | "other" (`license_name: sms-spam-collection-v1`) | Parquet | Deduplicated UCI (5,159 unique). Custom licence is **not** a standard commercial-friendly licence; treat as research-only. |
| `dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset` | https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset | English + machine translations (incl. `text_hi`) | 5,574 | GPL (version unverified) | Parquet; `labels`, `text`, `text_hi`, ... | UCI machine-translated into 20+ languages. Hindi column is MT output, not natural Hinglish; GPL makes reuse awkward. |
| Super SMS Dataset (spstudy) | https://github.com/smspamresearch/spstudy/blob/main/Data/super_sms_dataset.csv | Mostly English (global) | 67,016 | No licence file (repo `license: null`) — unverified/unusable commercially | CSV; `SMSes,Labels` (label 0/1) | 2012-2024 consolidated corpus, 6.7 MB, associated with IEEE Access 2024 paper. No licence means do not ship; could be used for internal evaluation only. |
| `alusci/sms-otp-spam-dataset` (HF) | https://huggingface.co/datasets/alusci/sms-otp-spam-dataset | English | 10,000 synthetic OTP SMS | MIT | CSV/Parquet; label = valid / not valid | Synthetic OTP templates; labels are "valid OTP" not scam/ham. Low value for this classifier. |

Usable shortlist for English: UCI (5.5k), Mendeley smishing (6k), plus Indian
English sets from section 4. Skip GPL/custom/no-licence sets for shipped models.

## 2. SMS Hindi / Hinglish

| Name | URL | Languages | Rows (spam/ham) | License | Columns/format | Notes |
|---|---|---|---|---|---|---|
| Spam SMS in Hindi Language (IEEE DataPort) | https://ieee-dataport.org/documents/spam-sms-hindi-language | Hindi (Devanagari) | 3,894 (1,404 spam / 2,490 ham) | "Creative Commons Attribution" on page; access requires IEEE DataPort subscription, paper says academic/non-commercial use | `Hindi.csv`; `Message`, `Label` | DOI 10.21227/5y8x-n678. Real crowdsourced messages (NIT Silchar, 2024). Best real Hindi set found, but redistribution/access is gated and the paper limits use to non-commercial research. |
| Indian SMS spam (princebari GitHub) | https://github.com/princebari/-SMS-Spam-Classification-on-Indian-Dataset-A-Crowdsourced-Collection-of-Hindi-and-English-Messages | Hindi, Hinglish, English | 1,999 | No licence (`license: null`) — unknown | `indian_spam.csv`; `v1` (ham/spam), `v2` (text) | Real crowdsourced Indian messages, older (2023 repo). Useful for validation, but cannot be shipped without permission. |
| `anmolshrivastav/scam_ham_india_14_languages` (HF) | https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages | 14 Indian language variants incl. Hindi and romanised Hinglish (`hi-Latn`), Tamil | 14,000 (7,000 scam / 7,000 ham; 1,000 per language) | MIT | Parquet; `text`, `label` (ham/scam), `language` | Fully synthetic, balanced, clean template style. Good for coverage, not for realism. Exact per-language spam/ham split **unverified**. |
| Indian Scam SMS (synthetic, audited) | https://huggingface.co/datasets/Ridham115/indian-scam-sms-synthetic-audited | English, Hindi (Devanagari), Hinglish, Roman-script Tamil/Telugu/Bengali/Marathi | 1,580 (label distribution per language unverified) | CC-BY-4.0 | CSV; `row_id`, `text`, `label` (safe/scam), `original_label`, `scam_type`, `language`, `generator`, `topic`, `audit_action` | LLM-generated but label-audited; explicitly built around Indian hard negatives (bank, courier, bill, job). Useful as augmentation, not as the only real-data proxy. |
| `bolewara/hinglish-scam-text-dataset` (HF) | https://huggingface.co/datasets/bolewara/hinglish-scam-text-dataset | Hinglish + English | 3,787 total; only ~63 Hinglish (35 scam / 28 benign); rest English | CC-BY-4.0 | JSON; `text`, `label` 0/1 | Hand-written Hinglish scam sentences exist but are too few to train on; English portion is itself small. |
| Indian Multilingual Scam Message Dataset | https://huggingface.co/datasets/karanverma19/Indian_Multilingual_Scam_Message_Dataset | Hindi, Hinglish, English | 120 | Apache-2.0 | CSV; `message`, `label`, `reason`, `domain`, `language` | Tiny, but the `reason` column is directly useful as few-shot explanation data for Llama. |
| Indian Cyber Scam PhoneCall Hinglish Dataset | https://huggingface.co/datasets/ysangam/Indian_Cyber_Scam_PhoneCall_Hinglish_Dataset | Hinglish, Hindi, English | 10,000 | Apache-2.0 | CSV/tabular; `text`, `label` 0/1, `scam_category`, `caller_type`, `audio_duration`, `urgency_level`, `contains_blackmail`, `language_style` | Phone-call transcripts, not SMS; useful for scam phrasing/explanation and for digital-arrest style scenarios. Many identical mirrors exist. |

No verified public corpus of *natural* Hinglish scam SMS at scale was found.
Real Hinglish is limited to ~2k mixed rows (princebari) plus ~63 hand-written
rows (bolewara); everything else is translated or synthetic.

## 3. SMS Tamil / Tanglish

| Name | URL | Languages | Rows (spam/ham) | License | Columns/format | Notes |
|---|---|---|---|---|---|---|
| Spam SMS in Dravidian Languages (IEEE DataPort) | https://ieee-dataport.org/documents/spam-sms-dravidian-languages | English, Tamil, Telugu, Kannada, Malayalam; includes Tamil written in Latin script (Tanglish) | ~7,700 total; Tamil subset 1,176 (212 spam / 963 ham per SMSDHL Table 3) | "Creative Commons Attribution" on page; subscription-gated; paper says academic/non-commercial | `Spam Message Collection.xlsx`; `Message`, `Type` | DOI 10.21227/dcym-pd69. Materially the only real Tamil/Tanglish spam SMS source found. Paper table sums to 1,175 for Tamil (minor source inconsistency). |
| SMSDHL paper (dataset description) | https://doi.org/10.36227/techrxiv.173603655.53756505/v1 | English, Tamil, Telugu, Kannada, Malayalam, Hindi | 11,611 total (2,799 spam / 8,812 ham); Tamil 1,176, Hindi 3,894 | Paper: academic/non-commercial | Table 3 statistics only | Confirms counts and the "Tamil verbatim written in English" (Tanglish) content. Dataset itself is on IEEE DataPort. |
| `anmolshrivastav/scam_ham_india_14_languages` | https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages | Tamil (script) + 13 other Indian variants | 1,000 Tamil (balanced overall; per-language split unverified) | MIT | Parquet; `text`, `label`, `language` | Synthetic; no Tanglish-specific column, but romanised code-mixed variants exist in the dataset card. |
| Indian Scam SMS (synthetic, audited) | https://huggingface.co/datasets/Ridham115/indian-scam-sms-synthetic-audited | Includes Roman-script Tamil + English code-mixing | Subset of 1,580 (Tamil count unverified) | CC-BY-4.0 | CSV; `language` field e.g. `te_en`, `hi_en`; `label` | Only ~hundreds of Tamil rows at most; synthetic. |
| Multilingual Scam Detection paper (Tamil/Tanglish) | https://journals.designone.press/index.php/jhcdm/article/view/22 | English, Tamil, Tanglish | 2,120 (1,484 train / 318 val / 318 test; test = 150 Tamil, 150 Tanglish, 18 English) | Public availability unverified | Not stated | The paper itself reports near-duplicate leakage (5,211 pairs >= 0.90 similarity), so even if released it needs template-disjoint splitting. Do not assume downloadable. |

Gap: no verified, openly licensed, naturally collected Tamil-script or Tanglish
scam SMS dataset. IEEE DataPort is subscription-gated and non-commercial per the
paper; everything else synthetic.

## 4. Indian-specific scam SMS (all languages)

| Name | URL | Languages | Rows (spam/ham) | License | Columns/format | Notes |
|---|---|---|---|---|---|---|
| `CloveAI/india-spam-sms` (HF) | https://huggingface.co/datasets/CloveAI/india-spam-sms | English (Indian context) | 20,010 | MIT | Parquet; `text`, `label` (int64; 0/1 mapping unverified but implied) | Explicit Indian categories: KYC, electricity disconnection, courier, jobs, loan apps, UPI. Clearly template-generated (identical sentence frames with slots), which inflates accuracy if test rows share templates. Mirrors: `MaloRaj/india-spam-sms`, `sahil456838/india-spam-sms` (MIT). |
| Scam/Spam India Dataset | https://huggingface.co/datasets/carnageiron/scam-ham-india | English | 2,272 (895 spam/scam / 1,377 ham) | Apache-2.0 | CSV; `text`, `label` (ham, spam/scam) | Real-world samples merged with synthetic augmentation for lottery, Aadhaar/KYC, UPI, jobs, OTP. Small but directly on-target. Duplicate copies exist (`anmolshrivastav/scam-ham-india`). |
| Indian Scam SMS (synthetic, audited) | https://huggingface.co/datasets/Ridham115/indian-scam-sms-synthetic-audited | English, Hindi, Hinglish, Roman Tamil/Telugu/Bengali/Marathi | 1,580 | CC-BY-4.0 | CSV; `text`, `label`, `scam_type`, `language`, `topic`, `audit_action` | Best synthetic set for hard negatives (real-looking banks, couriers, bills, jobs) with explicit audit trail. |
| `anmolshrivastav/scam_ham_india_14_languages` | https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages | 14 Indian variants | 14,000 (7,000/7,000) | MIT | Parquet; `text`, `label`, `language` | Broad language coverage, synthetic. |
| `bolewara/hinglish-scam-text-dataset` | https://huggingface.co/datasets/bolewara/hinglish-scam-text-dataset | Hinglish, English | 3,787 (tiny Hinglish scam subset) | CC-BY-4.0 | JSON; `text`, `label` | Real hand-written Hinglish scam examples, but only ~35. |
| Indian SMS spam (princebari) | https://github.com/princebari/-SMS-Spam-Classification-on-Indian-Dataset-A-Crowdsourced-Collection-of-Hindi-and-English-Messages | Hindi, Hinglish, English | 1,999 | Unknown (no licence) | CSV; `v1` (label), `v2` (text) | Real Indian messages; licence blocks shipping. |
| Indian Multilingual Scam Message Dataset | https://huggingface.co/datasets/karanverma19/Indian_Multilingual_Scam_Message_Dataset | Hindi, Hinglish, English | 120 | Apache-2.0 | CSV; `message`, `label`, `reason`, `domain`, `language` | Includes reasoning text; useful for explanations/few-shot. |
| `Shreyy24/chakravyuh-bench-v0` (HF) | https://huggingface.co/datasets/Shreyy24/chakravyuh-bench-v0 | English, Hindi, Tamil, Telugu, Kannada, Bengali, Marathi | 175 (144 scam / 31 non-scam) | CC-BY-4.0 | JSONL (`scenarios.jsonl`) | UPI-fraud benchmark, test-only; do not train on it. |
| Indian Cyber Scam PhoneCall Hinglish Dataset | https://huggingface.co/datasets/ysangam/Indian_Cyber_Scam_PhoneCall_Hinglish_Dataset | Hinglish, Hindi, English | 10,000 | Apache-2.0 | `text`, `label`, `scam_category`, `caller_type`, ... | Call transcripts; digital-arrest/urgency/blackmail flags useful for explanation templates. |
| India Cyber Scam Hinglish Dataset (Kaggle) | https://www.kaggle.com/datasets/sngmyd/india-cyber-scam-hinglish-dataset | Hinglish/English (claimed) | "500,000" claimed — **unverified** | **unverified** | **unverified** | Kaggle page blocked (JS/reCAPTCHA); cannot verify rows, licence, or content. Treat as lead only. |
| India Spam SMS Classification (Kaggle) | https://www.kaggle.com/datasets/junioralive/india-spam-sms-classification | **unverified** | **unverified** | **unverified** | **unverified** | Page exists but content unreadable via fetch. Do not rely on it. |

Category coverage in the verified sources is strongest for UPI/KYC, electricity,
courier, job/task, loan apps and OTP; digital arrest and fake-government
("PAN blocked") appear mostly in synthetic sets (Ridham115, ysangam).

## 5. Phishing URLs

| Name | URL | Languages | Rows (spam/ham) | License | Columns/format | Notes |
|---|---|---|---|---|---|---|
| PhishTank (Cisco Talos) | https://data.phishtank.com/ (docs: https://phishtank.org/developer_info.php) | URLs (global) | Live feed; row count changes hourly (**unverified at scale**) | CC BY-SA 2.5; terms explicitly allow commercial use of the Data | CSV/JSON/XML; `phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target` | Only verified, online phishes. Requires descriptive User-Agent; app key for frequent automated downloads. Attribution + share-alike obligations. Best source of *current* phishing. |
| OpenPhish | https://openphish.com/ (terms: https://openphish.com/terms.html) | URLs | Free feed; row count **unverified** | Free feed for personal/academic research only; commercial use requires written consent | Plain-text URL list / API | Not usable for a commercial app without a licence. |
| PhiUSIIL Phishing URL Dataset | https://data.mendeley.com/datasets/shwpxscxy2/1 | URLs (global) | 235,795 (100,945 phishing / 134,850 legitimate) | CC BY 4.0 | CSV/XLSX; raw URL column presence **unverified** | DOI 10.17632/shwpxscxy2.1. Popular benchmark; check whether the released files keep the raw URL or only 50+ engineered features. |
| PhiLegit-100K | https://data.mendeley.com/datasets/726pyz4j53/1 | URLs | 100,000 (50,000 phishing / 50,000 legitimate) | CC BY 4.0 | CSV retaining original URL + label (per page) | DOI 10.17632/726pyz4j53.1. Built from PhiUSIIL + LegitPhish; balanced and recent. |
| Phishing URL dataset (Wangchuk) | https://data.mendeley.com/datasets/3jddhy2f6s/1 | URLs | 149,726 (54,807 phishing / 94,919 legitimate) | CC BY 4.0 | CSV | Built from Common Crawl CC-MAIN-2024-33 + PhishTank; recent benign sample. |
| Phishing URL dataset (Jishnu/Arthi) | https://data.mendeley.com/datasets/vfszbj9b36/1 | URLs | 450,176 (104,438 phishing / 345,738 legitimate) | CC BY 4.0 | CSV | DOI 10.17632/vfszbj9b36.1. Sources include PhishTank and Majestic Million; descriptions claims per-URL labels but column names **unverified**. |
| CompPhish | https://data.mendeley.com/datasets/fmbs4kp9wz/4 | URLs + HTML | 15,358 (7,204 phishing / 8,154 legitimate) | CC BY 4.0 | Raw URL + HTML files + 70 extracted features; labels 0/1 | Collected Sep 2024-Aug 2025. Needs feature extraction; HTML not needed by the current scaffold. |
| `Mitake/PhishingURLsANDBenignURLs` (HF) | https://huggingface.co/datasets/Mitake/PhishingURLsANDBenignURLs | URLs | 886,181 (label distribution unverified) | CC-BY-SA-4.0 | CSV/Parquet; `url`, `label` | Largest verified raw-URL set; share-alike licence applies to derived datasets. |
| `bgspaditya/phishing-dataset` (HF) | https://huggingface.co/datasets/bgspaditya/phishing-dataset | URLs | 651,191 | MIT | CSV; `url`, `type` | Row count matches the well-known "Malicious URLs" set; `type` includes phishing/malware/defacement/benign, so filter to benign vs phishing. Provenance on the card is empty (only `license: mit`). |
| `shawhin/phishing-site-classification` (HF) | https://huggingface.co/datasets/shawhin/phishing-site-classification | URLs | 3,000 (train split 2,100) | ODbL | Parquet; `text` (URL), `labels` (1=phishing) | Clean text/label pair, derived from Kaggle `taruntiwarihp/phishing-site-urls`. Small; good for smoke tests. |
| `alexkstern/phishing_urls` (HF) | https://huggingface.co/datasets/alexkstern/phishing_urls | URLs | 507,195 (train 481,835) | **unverified** (no licence tag) | CSV; `text`, `label` | Raw URLs without scheme; licence unknown, so research-only until clarified. |
| `pirocheto/phishing-url` (HF) | https://huggingface.co/datasets/pirocheto/phishing-url | URLs | 11,430 (50/50) | CC-BY-4.0 | Parquet; 89 columns: raw `url` + 87 numeric features + `status` (phishing/legitimate) | Features include page-content and external-service signals. Not usable by the current URL scaffold without recomputing its 12 features; can validate feature parity. |
| Majestic Million / Tranco (benign domain lists) | https://majestic.com/reports/majestic-million ; https://tranco-list.eu/ | Domains | 1,000,000 domains each | **unverified** (licence text not read) | CSV (`Majestic Million`: rank, domain) | Only for generating benign URLs, and only after confirming licence. Prefer benign rows already included in PhiUSIIL/PhiLegit/vfszbj9b36/Mitake. |

## 6. Licence check (publishable/commercial-friendly vs not)

Commercial-friendly, keep attribution:
- CC BY 4.0: UCI SMS Spam, Mendeley SMS PHISHING, PhiUSIIL, PhiLegit-100K, Wangchuk, vfszbj9b36, CompPhish, pirocheto, Ridham115, bolewara, Shreyy24.
- MIT: CloveAI india-spam-sms, anmolshrivastav 14 languages, alusci OTP, bgspaditya.
- Apache-2.0: carnageiron, karanverma19, ysangam.
- ODbL: shawhin (attribution + share-alike for the database).
- CC BY-SA 2.5/4.0: PhishTank, Mitake — usable commercially, but derivative *databases* must stay share-alike; document this and avoid mixing into a claimed-proprietary dataset.

Research-only / restricted / unknown — do not ship without permission:
- IEEE DataPort Hindi and Dravidian datasets: subscription-gated; paper states academic/non-commercial.
- OpenPhish free feed: non-commercial only.
- GPL: dbarbedillo multilingual SMS (GPL version unverified).
- Custom `sms-spam-collection-v1` licence: jngb-labs.
- No licence at all: spstudy Super SMS Dataset, princebari indian_spam, alexkstern HF dataset, Kaggle datasets (unverified).
- Majestic Million / Tranco: licence unverified.

Practical rule: a trained model's weights are usually not a derivative of the
dataset, but redistributing the dataset itself is. Keep a per-source manifest
with URL, licence, DOI and download date, and exclude restricted sources from
anything shipped or published as data.

## 7. Recommended training mix and gaps

SMS classifier (TF-IDF + logistic regression):
- English real base: UCI 5,574 + Mendeley smishing 5,971 -> ~11.5k, dedupe to
  ~10k. Merge spam + smishing into label 1; keep Mendeley URL column for the
  URL classifier.
- Indian real English/Hinglish/Hindi: carnageiron 2,272 + princebari 1,999
  (internal use only) + bolewara Hinglish 63 + karanverma 120 (also keep
  reasons) = ~4.4k.
- Hindi real (if IEEE access is granted): 3,894. Otherwise rely on synthetic
  Hindi/Hinglish and state the limitation.
- Tamil/Tanglish real (if IEEE access is granted): 1,176. Otherwise synthetic.
- Synthetic augmentation (cap at 40-50% of training and always downweight):
  CloveAI 20,010 (cap/sample), anmol 14,000 (sample ~4-5k), Ridham115 1,580.
- Suggested blend: ~10k English real + ~4k Indian real + ~3.9k Hindi +
  ~1.2k Tamil real + ~6-8k synthetic (stratified by language/category) =
  roughly 25-30k rows, with a real-only, template-disjoint test set of
  ~2-3k rows. Keep ham:spam between 2:1 and 4:1; synthetic sets are near
  balanced, so downsample their spam if needed.
- Do not train on Shreyy24 (test-only benchmark) and do not let near-duplicate
  template families straddle train/test (group split by template/source).

URL classifier:
- Current phishing: PhishTank `online-valid.csv` (hourly, CC BY-SA 2.5).
- Historical balanced: PhiLegit-100K (100k) and/or PhiUSIIL (236k), plus
  vfszbj9b36 (450k) or Mitake (886k) for scale.
- If using bgspaditya (651k), filter `type` to benign vs phishing and drop
  malware/defacement; provenance is undocumented.
- Suggested: ~200k phishing + ~200k benign after dedupe by registrable domain,
  with a temporal test set (2025-2026 phishing) and hostname-disjoint splits.
  Avoid testing on domains seen in training; URL features (length, TLD,
  hyphens, punycode, etc.) leak trivially across mirrors.

Gaps:
- No verified, openly licensed, naturally collected Tamil-script or Tanglish
  scam SMS corpus; only gated IEEE data and synthetic rows.
- Natural Hinglish scam SMS is extremely scarce (~2k mixed + ~63 pure).
- Digital-arrest, fake "PAN blocked"/government, and courier/customs scripts
  exist mainly in synthetic sets; collect a small real evaluation set.
- Existing public Indian sets are template-heavy; near-duplicate leakage will
  overstate accuracy. Report template-disjoint metrics.
- Licence risk: the two best real Indian-language sources are the IEEE
  subscription datasets; several GitHub/HF copies have no licence.
- PII: SMS corpora may contain phone numbers/names; scrub before shipping or
  publishing. Mendeley smishing set includes phone/email columns.
- Age: UCI is from 2011, PhishTank feed is current, Mendeley URL sets are
  2023-2025; expect vocabulary drift in UPI/electricity/courier scams.

## 8. Converting a dataset to `tools/sms_classifier/train.py` CSV

The trainer expects a CSV with `text,label` where label is 0 (safe/ham) or
1 (threat/spam/scam). Steps:

1. Read the source with UTF-8 (strip BOM). Never re-encode Devanagari/Tamil
   through a legacy codepage.
2. Map columns:
   - UCI / `ucirvine/sms_spam`: `sms -> text`, `label` "ham"->0, "spam"->1.
   - Mendeley f45bkkt8pr: `TEXT -> text`; `LABEL` ham->0, spam/smishing->1.
   - CloveAI: `text` unchanged; confirm `label` 0/1 (int64) and that 1 means
     scam; otherwise invert.
   - carnageiron: `text` unchanged; `label` ham->0, spam/scam->1.
   - princebari: `v2 -> text`, `v1` ham->0, spam->1.
   - anmolshrivastav: `text` unchanged, `label` ham->0, scam->1; optionally
     filter by `language`.
   - Ridham115: `text` unchanged, `label` safe->0, scam->1; keep `language`
     and `scam_type` in a sidecar for error analysis.
   - bolewara: JSON `text`, `label` 0/1 -> same mapping; expect both English
     and Hinglish in one file.
   - karanverma19: `message -> text`, `label` scam->1, legit->0; save
     `reason` separately for explanation prompts.
3. Clean: trim whitespace, drop empty/very short (<3 chars) rows, drop exact
   duplicates, then near-duplicate dedupe (e.g., character 3-gram Jaccard >=
   0.9 or MinHash) before splitting.
4. PII scrub: replace phone numbers, emails, URLs, account/UPI IDs with
   placeholders *unless* the URL/text is needed as a feature; keep a raw-only
   copy outside the repo if reproducibility requires it.
5. Write `train.csv` / `test.csv` with only `text,label` (no index column,
   quoted fields, UTF-8, `\n` line endings). Shuffle with a fixed seed and
   split by template/source group, not by row, for the final evaluation.
6. Sanity check: print label counts per language and a few examples; ensure no
   duplicate `text` across train/test.

For URLs (`tools/url_classifier/train.py`), normalise to `url,label`:
add `https://` when no scheme, lowercase the host, keep the path/query, label
phishing=1 / benign=0, dedupe by registrable domain, then extract the 12
features in the existing scaffold rather than reusing another paper's 87
features.

## 9. Sources (fetched during this research)

Dataset pages and APIs:
- https://archive.ics.uci.edu/dataset/228/sms+spam+collection
- https://huggingface.co/datasets/ucirvine/sms_spam
- https://datasets-server.huggingface.co/splits?dataset=ucirvine/sms_spam
- https://datasets-server.huggingface.co/statistics?dataset=ucirvine/sms_spam&config=plain_text&split=train
- https://huggingface.co/datasets/codesignal/sms-spam-collection
- https://huggingface.co/datasets/jngb-labs/sms-spam
- https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset
- https://data.mendeley.com/datasets/f45bkkt8pr/1
- https://github.com/smspamresearch/spstudy
- https://github.com/smspamresearch/spstudy/tree/main/Data
- https://api.github.com/repos/smspamresearch/spstudy/contents/Data/super_sms_dataset.csv
- https://huggingface.co/datasets/alusci/sms-otp-spam-dataset
- https://ieee-dataport.org/documents/spam-sms-hindi-language
- https://ieee-dataport.org/documents/spam-sms-dravidian-languages
- https://doi.org/10.36227/techrxiv.173603655.53756505/v1
- https://github.com/princebari/-SMS-Spam-Classification-on-Indian-Dataset-A-Crowdsourced-Collection-of-Hindi-and-English-Messages
- https://api.github.com/repos/princebari/-SMS-Spam-Classification-on-Indian-Dataset-A-Crowdsourced-Collection-of-Hindi-and-English-Messages/contents/
- https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages
- https://huggingface.co/datasets/anmolshrivastav/scam-ham-india
- https://huggingface.co/datasets/Ridham115/indian-scam-sms-synthetic-audited
- https://huggingface.co/datasets/bolewara/hinglish-scam-text-dataset
- https://huggingface.co/datasets/karanverma19/Indian_Multilingual_Scam_Message_Dataset
- https://huggingface.co/datasets/ysangam/Indian_Cyber_Scam_PhoneCall_Hinglish_Dataset
- https://huggingface.co/datasets/CloveAI/india-spam-sms
- https://huggingface.co/datasets/carnageiron/scam-ham-india
- https://huggingface.co/api/datasets/carnageiron/scam-ham-india
- https://huggingface.co/datasets/Shreyy24/chakravyuh-bench-v0
- https://huggingface.co/api/datasets?search=scam%20india&limit=50
- https://huggingface.co/api/datasets?search=phishing&limit=50
- https://www.kaggle.com/datasets/sngmyd/india-cyber-scam-hinglish-dataset (blocked)
- https://www.kaggle.com/datasets/junioralive/india-spam-sms-classification (blocked)
- https://journals.designone.press/index.php/jhcdm/article/view/22

Phishing URL sources:
- https://data.phishtank.com/
- https://phishtank.org/developer_info.php
- https://www.phishtank.com/terms.php
- https://openphish.com/terms.html
- https://data.mendeley.com/datasets/shwpxscxy2/1
- https://data.mendeley.com/datasets/726pyz4j53/1
- https://data.mendeley.com/datasets/3jddhy2f6s/1
- https://data.mendeley.com/datasets/vfszbj9b36/1
- https://data.mendeley.com/datasets/fmbs4kp9wz/4
- https://huggingface.co/datasets/Mitake/PhishingURLsANDBenignURLs
- https://huggingface.co/datasets/bgspaditya/phishing-dataset
- https://huggingface.co/datasets/shawhin/phishing-site-classification
- https://huggingface.co/datasets/alexkstern/phishing_urls
- https://huggingface.co/datasets/pirocheto/phishing-url
- https://majestic.com/reports/majestic-million
- https://tranco-list.eu/
- https://datasets-server.huggingface.co/size
- https://datasets-server.huggingface.co/first-rows

Note: Kaggle row counts, licences and contents could not be verified because the
pages return only their title to a plain HTTP fetch. They are listed above as
leads, not as verified datasets.

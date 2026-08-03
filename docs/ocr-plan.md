# Future offline OCR layer: initial interface plan

This document reserves the trust boundary and coverage model for a future visual-content scanner. OCR is **not implemented or enabled** in the current AARK mining command. An image whose raw bytes yield no finding has not thereby been cleared of credentials that are visible only after rendering.

## Separate coverage layers

A future scan will report two independent coverage dimensions:

1. `raw bytes scanned`: the existing mining layer examined file bytes, cleartext, embedded structures, and metadata with the current detector semantics.
2. `visual content OCR-scanned`: a supported image/page/frame was decoded, rendered, recognized, and its bounded recognized text was examined.

Raw-byte completion must never imply visual OCR completion. An unsupported image, malformed input, decode/OCR limit, engine error, or interrupted OCR job prevents a claim of complete visual coverage for that source. It does not invalidate independently completed raw-byte coverage. A future classifier may route supported images into an OCR queue even when a sound raw-byte prefilter skips one or more byte detector families; routing is not a clean verdict.

## Proposed offline job interface

OCR must be explicitly enabled and its local dependencies must be installed deliberately. No hosted OCR, cloud API, remote model, provider lookup, telemetry, upload, or network validation is permitted. Before an OCR dependency is added, its package, version, license/usage terms, and installation path must be documented in `THIRD_PARTY.md` and the platform matrix.

Each pure OCR job should receive an immutable, bounded local source reference or decoded pixel/page buffer plus versioned options. The implementation must bound, before expensive work where possible:

- encoded input bytes;
- image width and height, decoded pixel count, color depth, and memory;
- document pages and animated-image frames;
- regions attempted per page/frame;
- decoder and OCR wall/CPU runtime;
- recognized text bytes; and
- generated text, region, and preprocessing artifact bytes.

Decoders must reject decompression bombs, recursive/container amplification, unsupported encodings, and malformed images without unbounded retries or allocations. Preprocessing (orientation, scaling, colorspace, thresholding, language set, segmentation, and region selection) should be deterministic and versioned wherever practical.

An OCR response must contain bounded recognized text and no external references. Its local metadata should record:

- SHA-256 of the original source image/document;
- OCR engine and exact version;
- decoder and preprocessing version/options;
- page or frame number;
- region/bounding box in a documented coordinate system;
- OCR confidence and language/model identifier; and
- limit, unsupported-format, or failure status without embedding recognized secret values in routine logs.

The main thread—not an OCR worker—must verify response bounds and source identity, feed recognized text into the same pure secret detectors or a clearly versioned text-detection interface, deduplicate, assign deterministic IDs, account capacity, and publish artifacts/checkpoints in source/page/region order. Exact OCR text and useful region/preprocessing artifacts remain local, private, integrity-hashed, and absent from redacted reports.

## Provenance, retention, and reports

A distinct provenance such as `ocr-derived` may be introduced only with one consistent type-system, report, cleanup, resume, documentation, and synthetic-test update. It must identify a visual derivation rather than suggest that the recognized characters were present as raw encoded bytes.

When OCR produces a recognized sensitive finding, cleanup must preserve the **whole original image/document**, not only a crop or OCR transcript. The private inventory should integrity-link that source to the OCR engine/version, page/frame, region, confidence, recognized-text artifact, and any retained region artifact. Existing whole-source retention rules are the intended foundation, but cleanup must explicitly understand the OCR provenance before it may accept an OCR-authorized scan.

Reports must state raw-byte and OCR coverage separately, count unsupported/failed/limited visual sources, and avoid claiming complete OCR coverage when any routed source lacks a successful terminal OCR result. QR/barcode-derived text is outside the initial OCR promise unless a bounded offline decoder is explicitly added and reported as a separate recognized-text source.

## Required tests before implementation is usable

Use only generated synthetic images/documents. Tests must cover deterministic ordering across worker counts, text split across regions/pages, rotations and supported encodings, duplicate visual findings, bounding-box validation, source replacement, malformed inputs, decompression bombs, every configured bound, clean pause/resume, artifact corruption, redaction, and whole-original-source retention. OCR failures must downgrade only visual coverage, while raw-byte failures must remain independently visible.

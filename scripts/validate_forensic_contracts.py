import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACT_DIR = ROOT / "contracts"


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def assert_true(condition: bool, message: str):
    if not condition:
        raise ValueError(message)


def validate_evidence_manifest(data: dict):
    required = [
        "schema_version",
        "case_id",
        "evidence_id",
        "source",
        "hashes",
        "ingested_at_utc",
    ]
    for key in required:
        assert_true(key in data, f"Evidence manifest missing required field: {key}")

    assert_true(isinstance(data["source"], dict), "source must be an object")
    for key in ["type", "path", "size_bytes"]:
        assert_true(key in data["source"], f"source missing required field: {key}")

    assert_true(isinstance(data["hashes"], dict), "hashes must be an object")
    hash_algorithms = ["sha256", "sha1", "md5"]
    assert_true(any(algo in data["hashes"] for algo in hash_algorithms), "hashes must include at least one of sha256/sha1/md5")


def validate_artifact_provenance(data: dict):
    required = [
        "schema_version",
        "artifact_id",
        "artifact_type",
        "case_id",
        "evidence_id",
        "parser",
        "source_reference",
        "extracted_at_utc",
    ]
    for key in required:
        assert_true(key in data, f"Artifact provenance missing required field: {key}")

    assert_true(isinstance(data["parser"], dict), "parser must be an object")
    for key in ["module", "version"]:
        assert_true(key in data["parser"], f"parser missing required field: {key}")

    assert_true(isinstance(data["source_reference"], dict), "source_reference must be an object")
    assert_true(any(k in data["source_reference"] for k in ["record_id", "offset_bytes", "path"]), "source_reference must include record_id, offset_bytes, or path")


def main():
    evidence_schema = CONTRACT_DIR / "evidence.manifest.schema.json"
    provenance_schema = CONTRACT_DIR / "artifact.provenance.schema.json"
    evidence_example = CONTRACT_DIR / "examples" / "evidence.manifest.example.json"
    provenance_example = CONTRACT_DIR / "examples" / "artifact.provenance.example.json"

    for path in [evidence_schema, provenance_schema, evidence_example, provenance_example]:
        assert_true(path.exists(), f"Missing contract file: {path}")

    evidence_data = load_json(evidence_example)
    provenance_data = load_json(provenance_example)

    validate_evidence_manifest(evidence_data)
    validate_artifact_provenance(provenance_data)

    print("Forensic contracts validation passed.")


if __name__ == "__main__":
    main()

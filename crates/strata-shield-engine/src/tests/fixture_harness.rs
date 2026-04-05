#[cfg(test)]
mod fixture_harness_tests {
    use crate::classification::dump::parse_dump_header;
    use crate::classification::{
        extract_audio_metadata, extract_image_exif, extract_video_metadata,
        parse_office_properties, parse_pdf_header, parse_search_index, parse_wim_header,
        scan_search_history,
    };
    use crate::disk::{detect_image_format, get_image_segments, ImageFormat};
    use serde::Deserialize;
    use std::collections::{HashMap, HashSet};
    use std::env;
    use std::fs::File;
    use std::io::Read;
    use std::path::{Path, PathBuf};

    #[derive(Debug, Deserialize, Default)]
    struct FixtureManifest {
        #[allow(dead_code)]
        version: Option<u32>,
        #[allow(dead_code)]
        fixtures: Option<Vec<FixtureRecord>>,
        parser_inputs: Option<Vec<ParserInput>>,
    }

    #[derive(Debug, Deserialize)]
    struct FixtureRecord {
        #[allow(dead_code)]
        id: String,
        #[allow(dead_code)]
        platform: Option<String>,
        #[allow(dead_code)]
        kind: Option<String>,
        #[allow(dead_code)]
        path: String,
        #[allow(dead_code)]
        notes: Option<String>,
        #[serde(default)]
        expected_detect_format: Option<String>,
        #[serde(default)]
        expected_segment_count: Option<usize>,
        #[serde(default)]
        expected_parser_outcomes: Option<HashMap<String, String>>,
    }

    #[derive(Debug, Deserialize)]
    struct ParserInput {
        id: String,
        parser: String,
        path: String,
        #[serde(default)]
        input_mode: Option<String>,
        #[serde(default)]
        max_bytes: Option<usize>,
        #[serde(default)]
        expect_ok: Option<bool>,
    }

    const DEFAULT_PARSER_MAX_BYTES: usize = 2 * 1024 * 1024;
    const DEFAULT_CORPUS_MAX_BYTES: usize = 2 * 1024 * 1024;
    const DEFAULT_CORPUS_MAX_FILES: usize = 200;

    #[test]
    fn test_fixture_manifest_is_readable() {
        let manifest = load_manifest();
        let _ = manifest.version.unwrap_or(1);
        let _ = manifest.fixtures.unwrap_or_default().len();
    }

    #[test]
    fn test_fixture_manifest_audit() {
        let manifest = load_manifest();
        let fixtures = manifest.fixtures.unwrap_or_default();
        let parser_inputs = manifest.parser_inputs.unwrap_or_default();
        if fixtures.is_empty() && parser_inputs.is_empty() {
            return;
        }

        let strict = env_flag_enabled("FORENSIC_FIXTURE_STRICT");
        let root = find_repo_root().expect("repo root with fixtures/images should exist");
        let images_root = root.join("fixtures").join("images");

        let mut missing_fixture_paths = Vec::new();
        for fixture in &fixtures {
            let abs = images_root.join(&fixture.path);
            if !abs.exists() {
                missing_fixture_paths.push(fixture.path.clone());
            }
        }

        let mut unknown_parsers = Vec::new();
        let mut invalid_parser_paths = Vec::new();
        for input in &parser_inputs {
            let mode = input.input_mode.as_deref().unwrap_or("bytes");
            if !is_supported_parser_key(&input.parser, mode) {
                unknown_parsers.push(format!("{} ({})", input.id, input.parser));
            }
            let abs = images_root.join(&input.path);
            if !abs.exists() {
                invalid_parser_paths.push(format!("{} -> {}", input.id, input.path));
            }
        }

        let duplicate_fixture_ids = find_duplicate_ids(fixtures.iter().map(|f| f.id.as_str()));
        let duplicate_parser_input_ids =
            find_duplicate_ids(parser_inputs.iter().map(|p| p.id.as_str()));
        let mut invalid_expected_formats = Vec::new();
        let mut invalid_expected_parser_keys = Vec::new();
        let mut invalid_expected_parser_outcomes = Vec::new();
        for fixture in &fixtures {
            if let Some(expected) = fixture.expected_detect_format.as_deref() {
                if !is_valid_format_label(expected) {
                    invalid_expected_formats.push(format!("{} -> {}", fixture.id, expected));
                }
            }
            if let Some(expectations) = &fixture.expected_parser_outcomes {
                for (parser, outcome) in expectations {
                    if !is_supported_expectation_parser_key(parser) {
                        invalid_expected_parser_keys.push(format!("{} -> {}", fixture.id, parser));
                    }
                    if parse_expected_outcome(outcome).is_none() {
                        invalid_expected_parser_outcomes
                            .push(format!("{} -> {}={}", fixture.id, parser, outcome));
                    }
                }
            }
        }

        let referenced_paths: HashSet<&str> = parser_inputs
            .iter()
            .map(|input| input.path.as_str())
            .collect();
        let unreferenced_fixtures: Vec<String> = fixtures
            .iter()
            .filter(|fixture| !referenced_paths.contains(fixture.path.as_str()))
            .map(|fixture| fixture.path.clone())
            .collect();

        let disk_format_paths: HashSet<&str> = parser_inputs
            .iter()
            .filter(|p| {
                p.parser == "disk-format" && p.input_mode.as_deref().unwrap_or("bytes") == "path"
            })
            .map(|p| p.path.as_str())
            .collect();
        let fixtures_without_disk_format: Vec<String> = fixtures
            .iter()
            .filter(|f| !disk_format_paths.contains(f.path.as_str()))
            .map(|f| f.path.clone())
            .collect();

        if !missing_fixture_paths.is_empty() {
            eprintln!(
                "[fixture-harness] manifest missing fixture files: {}",
                missing_fixture_paths.join(", ")
            );
        }
        if !invalid_parser_paths.is_empty() {
            eprintln!(
                "[fixture-harness] parser_inputs with missing files: {}",
                invalid_parser_paths.join(", ")
            );
        }
        if !duplicate_fixture_ids.is_empty() {
            eprintln!(
                "[fixture-harness] duplicate fixture ids: {}",
                duplicate_fixture_ids.join(", ")
            );
        }
        if !duplicate_parser_input_ids.is_empty() {
            eprintln!(
                "[fixture-harness] duplicate parser input ids: {}",
                duplicate_parser_input_ids.join(", ")
            );
        }
        if !invalid_expected_formats.is_empty() {
            eprintln!(
                "[fixture-harness] invalid expected_detect_format values: {}",
                invalid_expected_formats.join(", ")
            );
        }
        if !invalid_expected_parser_keys.is_empty() {
            eprintln!(
                "[fixture-harness] invalid expected_parser_outcomes parser keys: {}",
                invalid_expected_parser_keys.join(", ")
            );
        }
        if !invalid_expected_parser_outcomes.is_empty() {
            eprintln!(
                "[fixture-harness] invalid expected_parser_outcomes values: {}",
                invalid_expected_parser_outcomes.join(", ")
            );
        }
        if !unreferenced_fixtures.is_empty() {
            eprintln!(
                "[fixture-harness] fixtures without parser_inputs: {}",
                unreferenced_fixtures.join(", ")
            );
        }
        if !fixtures_without_disk_format.is_empty() {
            eprintln!(
                "[fixture-harness] fixtures without disk-format parser input: {}",
                fixtures_without_disk_format.join(", ")
            );
        }

        assert!(
            unknown_parsers.is_empty(),
            "manifest has unknown parser keys: {}",
            unknown_parsers.join(", ")
        );
        assert!(
            duplicate_fixture_ids.is_empty(),
            "manifest has duplicate fixture ids: {}",
            duplicate_fixture_ids.join(", ")
        );
        assert!(
            duplicate_parser_input_ids.is_empty(),
            "manifest has duplicate parser input ids: {}",
            duplicate_parser_input_ids.join(", ")
        );
        assert!(
            invalid_expected_formats.is_empty(),
            "manifest has invalid expected_detect_format values: {}",
            invalid_expected_formats.join(", ")
        );
        assert!(
            invalid_expected_parser_keys.is_empty(),
            "manifest has invalid expected_parser_outcomes parser keys: {}",
            invalid_expected_parser_keys.join(", ")
        );
        assert!(
            invalid_expected_parser_outcomes.is_empty(),
            "manifest has invalid expected_parser_outcomes values: {}",
            invalid_expected_parser_outcomes.join(", ")
        );

        if strict {
            assert!(
                missing_fixture_paths.is_empty(),
                "strict fixture audit failed: missing fixture files"
            );
            assert!(
                invalid_parser_paths.is_empty(),
                "strict fixture audit failed: some parser input paths are missing"
            );
            assert!(
                unreferenced_fixtures.is_empty(),
                "strict fixture audit failed: some fixtures are not referenced by parser_inputs"
            );
            assert!(
                fixtures_without_disk_format.is_empty(),
                "strict fixture audit failed: fixtures missing disk-format parser coverage"
            );
        }
    }

    #[test]
    fn test_fixture_kind_format_expectations() {
        let manifest = load_manifest();
        let fixtures = manifest.fixtures.unwrap_or_default();
        if fixtures.is_empty() {
            return;
        }

        let strict = env_flag_enabled("FORENSIC_FIXTURE_STRICT");
        let root = find_repo_root().expect("repo root with fixtures/images should exist");
        let images_root = root.join("fixtures").join("images");
        let mut kind_mismatches = Vec::new();
        let mut explicit_mismatches = Vec::new();

        for fixture in &fixtures {
            let abs = images_root.join(&fixture.path);
            if !abs.exists() {
                continue;
            }
            assert_segment_count_consistent(&abs);

            match detect_image_format(&abs) {
                Ok(info) => {
                    let detected = image_format_label(&info.format);
                    if let Some(kind) = fixture.kind.as_deref() {
                        if let Some(expected) = expected_format_labels_for_kind(kind) {
                            if !expected.contains(&detected) {
                                kind_mismatches.push(format!(
                                    "{} [{}]: expected one of {:?}, got {} ({})",
                                    fixture.path, kind, expected, detected, info.description
                                ));
                            }
                        }
                    }

                    if let Some(expected_detect_format) = fixture.expected_detect_format.as_deref()
                    {
                        if !format_matches_expected_label(&info.format, expected_detect_format) {
                            explicit_mismatches.push(format!(
                                "{}: expected_detect_format={}, got {} ({})",
                                fixture.path, expected_detect_format, detected, info.description
                            ));
                        }
                    }

                    if let Some(expected_segment_count) = fixture.expected_segment_count {
                        let actual_segments =
                            get_image_segments(&abs).map(|v| v.len()).unwrap_or(0);
                        if actual_segments != expected_segment_count {
                            explicit_mismatches.push(format!(
                                "{}: expected_segment_count={}, got {}",
                                fixture.path, expected_segment_count, actual_segments
                            ));
                        }
                    }
                }
                Err(err) => {
                    kind_mismatches.push(format!(
                        "{} [{}]: detect_image_format error: {}",
                        fixture.path,
                        fixture.kind.as_deref().unwrap_or("unknown"),
                        err_to_string(err)
                    ));
                }
            }
        }

        if !kind_mismatches.is_empty() {
            eprintln!(
                "[fixture-harness] kind-based format mismatches:\n{}",
                kind_mismatches.join("\n")
            );
        }
        if !explicit_mismatches.is_empty() {
            eprintln!(
                "[fixture-harness] explicit fixture expectation mismatches:\n{}",
                explicit_mismatches.join("\n")
            );
        }

        assert!(
            kind_mismatches.is_empty(),
            "fixture kind format mismatches:\n{}",
            kind_mismatches.join("\n")
        );
        if strict {
            assert!(
                explicit_mismatches.is_empty(),
                "strict fixture expectation mismatches:\n{}",
                explicit_mismatches.join("\n")
            );
        }
    }

    #[test]
    fn test_fixture_parser_expectations() {
        let manifest = load_manifest();
        let fixtures = manifest.fixtures.unwrap_or_default();
        if fixtures.is_empty() {
            return;
        }

        let strict = env_flag_enabled("FORENSIC_FIXTURE_STRICT");
        let root = find_repo_root().expect("repo root with fixtures/images should exist");
        let images_root = root.join("fixtures").join("images");
        let mut mismatches = Vec::new();

        for fixture in &fixtures {
            let Some(expectations) = &fixture.expected_parser_outcomes else {
                continue;
            };
            let abs = images_root.join(&fixture.path);
            if !abs.exists() {
                continue;
            }

            for (parser, expected_outcome) in expectations {
                let Some(expect_ok) = parse_expected_outcome(expected_outcome) else {
                    continue;
                };
                let actual = run_expectation_parser(parser, &abs);
                let actual_ok = actual.is_ok();

                if actual_ok != expect_ok {
                    mismatches.push(format!(
                        "{} [{}]: expected {}, got {} ({:?})",
                        fixture.path,
                        parser,
                        if expect_ok { "ok" } else { "error" },
                        if actual_ok { "ok" } else { "error" },
                        actual.err()
                    ));
                }
            }
        }

        if !mismatches.is_empty() {
            eprintln!(
                "[fixture-harness] parser expectation mismatches:\n{}",
                mismatches.join("\n")
            );
        }
        if strict {
            assert!(
                mismatches.is_empty(),
                "strict fixture parser expectation mismatches:\n{}",
                mismatches.join("\n")
            );
        }
    }

    #[test]
    fn test_parser_fixture_harness() {
        let manifest = load_manifest();
        let parser_inputs = manifest.parser_inputs.unwrap_or_default();
        if parser_inputs.is_empty() {
            return;
        }

        let root = find_repo_root().expect("repo root with fixtures/images should exist");
        let images_root = root.join("fixtures").join("images");
        let mut executed = 0usize;

        for input in parser_inputs {
            let abs = images_root.join(&input.path);
            if !abs.exists() {
                eprintln!(
                    "[fixture-harness] skipping missing input: {}",
                    abs.display()
                );
                continue;
            }

            let mode = input.input_mode.as_deref().unwrap_or("bytes");
            let expect_ok = input.expect_ok.unwrap_or(true);
            let result = match mode {
                "path" => run_path_parser(&input.parser, &abs),
                _ => {
                    let limit = input.max_bytes.unwrap_or(DEFAULT_PARSER_MAX_BYTES);
                    let bytes = read_prefix(&abs, limit).unwrap_or_else(|e| {
                        panic!("failed reading fixture {}: {e}", abs.display())
                    });
                    run_bytes_parser(&input.parser, &bytes)
                }
            };

            if expect_ok {
                assert!(
                    result.is_ok(),
                    "parser fixture {} ({}) failed: {:?}",
                    input.id,
                    input.parser,
                    result.err()
                );
            }
            executed += 1;
        }

        if executed == 0 {
            eprintln!("[fixture-harness] no parser inputs executed (all missing)");
        }
    }

    #[test]
    fn test_corpus_parser_harness_opt_in() {
        if !env_flag_enabled("FORENSIC_CORPUS_HARNESS") {
            eprintln!(
                "[fixture-harness] corpus harness skipped; set FORENSIC_CORPUS_HARNESS=1 to enable"
            );
            return;
        }

        let root = find_repo_root().expect("repo root with fixtures/images should exist");
        let images_root = root.join("fixtures").join("images");
        let max_files = env_usize("FORENSIC_CORPUS_MAX_FILES", DEFAULT_CORPUS_MAX_FILES);
        let max_bytes = env_usize("FORENSIC_CORPUS_MAX_BYTES", DEFAULT_CORPUS_MAX_BYTES);

        let files = collect_corpus_files(&images_root, max_files);
        if files.is_empty() {
            eprintln!("[fixture-harness] corpus harness found no candidate files");
            return;
        }

        let mut exercised = 0usize;
        let mut unreadable = 0usize;
        for path in files {
            assert_detect_format_stable(&path);
            assert_segment_count_consistent(&path);

            let bytes = match read_prefix(&path, max_bytes) {
                Ok(data) => data,
                Err(err) => {
                    unreadable += 1;
                    eprintln!(
                        "[fixture-harness] skipping unreadable corpus file {}: {}",
                        path.display(),
                        err
                    );
                    continue;
                }
            };

            assert_bytes_parser_stable("dump-header", &bytes, |data| {
                parse_dump_header(data).map(|v| format!("{:?}", v))
            });
            assert_bytes_parser_stable("wim-header", &bytes, |data| {
                parse_wim_header(data).map(|v| format!("{:?}", v))
            });
            assert_bytes_parser_stable("pdf-header", &bytes, |data| {
                parse_pdf_header(data).map(|v| format!("{:?}", v))
            });
            assert_bytes_parser_stable("office-properties", &bytes, |data| {
                parse_office_properties(data).map(|v| format!("{:?}", v))
            });
            assert_bytes_parser_stable("image-exif", &bytes, |data| {
                extract_image_exif(data).map(|v| format!("{:?}", v))
            });
            assert_bytes_parser_stable("audio-metadata", &bytes, |data| {
                extract_audio_metadata(data).map(|v| format!("{:?}", v))
            });
            assert_bytes_parser_stable("video-metadata", &bytes, |data| {
                extract_video_metadata(data).map(|v| format!("{:?}", v))
            });
            exercised += 1;
        }

        eprintln!(
            "[fixture-harness] corpus run complete: exercised={}, unreadable={}",
            exercised, unreadable
        );
        assert!(
            exercised > 0,
            "corpus harness did not exercise any readable corpus files"
        );
    }

    fn run_bytes_parser(parser: &str, data: &[u8]) -> Result<(), String> {
        match parser {
            "audio-metadata" => extract_audio_metadata(data)
                .map(|_| ())
                .map_err(err_to_string),
            "image-exif" => extract_image_exif(data).map(|_| ()).map_err(err_to_string),
            "office-properties" => parse_office_properties(data)
                .map(|_| ())
                .map_err(err_to_string),
            "pdf-header" => parse_pdf_header(data).map(|_| ()).map_err(err_to_string),
            "video-metadata" => extract_video_metadata(data)
                .map(|_| ())
                .map_err(err_to_string),
            "wim-header" => parse_wim_header(data).map(|_| ()).map_err(err_to_string),
            "dump-header" => parse_dump_header(data).map(|_| ()).map_err(err_to_string),
            _ => Err(format!("unsupported bytes parser key: {parser}")),
        }
    }

    fn run_path_parser(parser: &str, path: &Path) -> Result<(), String> {
        match parser {
            "search-index" => parse_search_index(path).map(|_| ()).map_err(err_to_string),
            "search-history" => scan_search_history(path).map(|_| ()).map_err(err_to_string),
            "disk-format" => detect_image_format(path).map(|_| ()).map_err(err_to_string),
            _ => Err(format!("unsupported path parser key: {parser}")),
        }
    }

    fn is_supported_parser_key(parser: &str, mode: &str) -> bool {
        match mode {
            "path" => matches!(parser, "search-index" | "search-history" | "disk-format"),
            _ => matches!(
                parser,
                "audio-metadata"
                    | "image-exif"
                    | "office-properties"
                    | "pdf-header"
                    | "video-metadata"
                    | "wim-header"
                    | "dump-header"
            ),
        }
    }

    fn is_supported_expectation_parser_key(parser: &str) -> bool {
        let mode = parser_mode_for_key(parser);
        is_supported_parser_key(parser, mode)
    }

    fn parser_mode_for_key(parser: &str) -> &'static str {
        match parser {
            "search-index" | "search-history" | "disk-format" => "path",
            _ => "bytes",
        }
    }

    fn parse_expected_outcome(value: &str) -> Option<bool> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ok" | "success" | "pass" | "true" | "1" => Some(true),
            "error" | "err" | "fail" | "false" | "0" => Some(false),
            _ => None,
        }
    }

    fn run_expectation_parser(parser: &str, path: &Path) -> Result<(), String> {
        match parser_mode_for_key(parser) {
            "path" => run_path_parser(parser, path),
            _ => {
                let bytes = read_prefix(path, DEFAULT_PARSER_MAX_BYTES)?;
                run_bytes_parser(parser, &bytes)
            }
        }
    }

    fn image_format_label(fmt: &ImageFormat) -> &'static str {
        match fmt {
            ImageFormat::Raw => "Raw",
            ImageFormat::E01 => "E01",
            ImageFormat::AFF => "AFF",
            ImageFormat::S01 => "S01",
            ImageFormat::Lx01 => "Lx01",
            ImageFormat::Lx02 => "Lx02",
            ImageFormat::Unknown => "Unknown",
            _ => "Other",
        }
    }

    fn expected_format_labels_for_kind(kind: &str) -> Option<Vec<&'static str>> {
        let k = kind.trim().to_ascii_lowercase();
        match k.as_str() {
            "e01" => Some(vec!["E01"]),
            "aff" => Some(vec!["AFF"]),
            "s01" => Some(vec!["S01"]),
            "lx01" => Some(vec!["Lx01"]),
            // Current detector classifies these containers/media as Raw unless a
            // known forensic-container signature is found in the header bytes.
            "iso" | "vdi" | "vhd" | "vhdx" | "vmdk" | "img" | "dd" | "raw" | "dmg" => {
                Some(vec!["Raw"])
            }
            // Segment file extension may belong to raw or segmented forensic sets.
            "001" => Some(vec!["Raw", "E01"]),
            _ => None,
        }
    }

    fn is_valid_format_label(label: &str) -> bool {
        matches!(
            label.trim().to_ascii_lowercase().as_str(),
            "raw" | "e01" | "aff" | "s01" | "lx01" | "lx02" | "unknown"
        )
    }

    fn format_matches_expected_label(format: &ImageFormat, expected_label: &str) -> bool {
        image_format_label(format).eq_ignore_ascii_case(expected_label.trim())
    }

    fn assert_detect_format_stable(path: &Path) {
        let first = detect_image_format(path)
            .map(|v| format!("{:?}", v))
            .map_err(err_to_string);
        let second = detect_image_format(path)
            .map(|v| format!("{:?}", v))
            .map_err(err_to_string);
        assert_eq!(
            first,
            second,
            "detect_image_format unstable for {}",
            path.display()
        );
    }

    fn assert_segment_count_consistent(path: &Path) {
        let detected = detect_image_format(path).unwrap_or_else(|e| {
            panic!(
                "detect_image_format failed for {}: {}",
                path.display(),
                err_to_string(e)
            )
        });
        let segments = get_image_segments(path).unwrap_or_else(|e| {
            panic!(
                "get_image_segments failed for {}: {}",
                path.display(),
                err_to_string(e)
            )
        });
        assert_eq!(
            detected.segment_count,
            segments.len(),
            "segment_count mismatch for {} (detected={}, enumerated={})",
            path.display(),
            detected.segment_count,
            segments.len()
        );
    }

    fn assert_bytes_parser_stable<F>(parser_name: &str, bytes: &[u8], parser: F)
    where
        F: Fn(&[u8]) -> Result<String, crate::errors::ForensicError>,
    {
        let first = parser(bytes).map_err(err_to_string);
        let second = parser(bytes).map_err(err_to_string);
        assert_eq!(
            first, second,
            "{} produced non-deterministic results",
            parser_name
        );
    }

    fn load_manifest() -> FixtureManifest {
        let Some(root) = find_repo_root() else {
            return FixtureManifest::default();
        };
        let manifest_path = root.join("fixtures").join("images").join("manifest.json");
        let Ok(data) = std::fs::read(manifest_path) else {
            return FixtureManifest::default();
        };
        serde_json::from_slice::<FixtureManifest>(&data).unwrap_or_default()
    }

    fn read_prefix(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
        let mut file = File::open(path).map_err(|e| format!("open failed: {e}"))?;
        let mut buf = vec![0u8; max_bytes];
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read failed: {e}"))?;
        buf.truncate(n);
        Ok(buf)
    }

    fn collect_corpus_files(images_root: &Path, max_files: usize) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![images_root.to_path_buf()];

        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };

            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if !is_corpus_candidate(&path) {
                    continue;
                }
                out.push(path);
                if out.len() >= max_files {
                    out.sort();
                    return out;
                }
            }
        }

        out.sort();
        out
    }

    fn is_corpus_candidate(path: &Path) -> bool {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .unwrap_or_default();
        matches!(
            ext.as_str(),
            "iso"
                | "e01"
                | "vdi"
                | "vhd"
                | "vhdx"
                | "vmdk"
                | "img"
                | "dd"
                | "raw"
                | "001"
                | "aff"
                | "s01"
                | "lx01"
                | "lx02"
                | "dmg"
                | "dmp"
                | "mem"
                | "vmem"
        )
    }

    fn env_flag_enabled(name: &str) -> bool {
        env::var(name)
            .ok()
            .map(|v| {
                let normalized = v.trim().to_ascii_lowercase();
                matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
            })
            .unwrap_or(false)
    }

    fn env_usize(name: &str, default_value: usize) -> usize {
        env::var(name)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(default_value)
    }

    fn find_duplicate_ids<'a, I>(ids: I) -> Vec<String>
    where
        I: Iterator<Item = &'a str>,
    {
        let mut seen = HashSet::new();
        let mut duplicates = HashSet::new();
        for id in ids {
            if !seen.insert(id.to_string()) {
                duplicates.insert(id.to_string());
            }
        }
        let mut out: Vec<String> = duplicates.into_iter().collect();
        out.sort();
        out
    }

    fn find_repo_root() -> Option<PathBuf> {
        let mut dir = env::current_dir().ok()?;
        for _ in 0..10 {
            if dir.join("fixtures").join("images").exists() {
                return Some(dir);
            }
            if !dir.pop() {
                break;
            }
        }
        None
    }

    fn err_to_string<E: std::fmt::Display>(e: E) -> String {
        e.to_string()
    }
}

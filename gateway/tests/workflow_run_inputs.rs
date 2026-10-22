//! Tripwire: GitHub Actions `run:` scripts in this repo must not expand
//! caller-controlled expressions (`${{ github.event.* }}`, `${{ inputs.* }}`,
//! `${{ github.head_ref }}`) directly into shell source. Such values are passed
//! through `env:` and referenced as shell variables instead. The release
//! workflows also validate the manually supplied release tag before writing it
//! to `$GITHUB_OUTPUT`.
//!
//! The checks are line-based over `.github/workflows/*.yml`, with negative
//! controls on inline fixtures so the scanner itself is proven to fire.

use std::path::{Path, PathBuf};

/// One `run:` script: the workflow-relative line it starts on and its text.
#[derive(Debug)]
struct RunBlock {
    line: usize,
    text: String,
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Extract every `run:` script from a workflow file (inline or block scalar).
fn run_blocks(src: &str) -> Vec<RunBlock> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        let key = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        if let Some(rest) = key.strip_prefix("run:") {
            let key_indent = indent_of(line) + (trimmed.len() - key.len());
            let rest = rest.trim();
            if rest.starts_with('|') || rest.starts_with('>') {
                let mut body = Vec::new();
                let mut j = i + 1;
                while j < lines.len() {
                    let l = lines[j];
                    if !l.trim().is_empty() && indent_of(l) <= key_indent {
                        break;
                    }
                    body.push(l);
                    j += 1;
                }
                out.push(RunBlock {
                    line: i + 1,
                    text: body.join("\n"),
                });
                i = j;
                continue;
            }
            out.push(RunBlock {
                line: i + 1,
                text: rest.to_string(),
            });
        }
        i += 1;
    }
    out
}

/// Contexts whose value a workflow caller or PR author controls.
const UNTRUSTED: &[&str] = &["github.event.", "inputs.", "github.head_ref"];

/// Every `${{ ... }}` expression in `text` that references an untrusted context.
fn untrusted_expressions(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("${{") {
        let after = &rest[start + 3..];
        let Some(end) = after.find("}}") else { break };
        let expr = after[..end].trim();
        if UNTRUSTED.iter().any(|u| expr.contains(u)) {
            found.push(expr.to_string());
        }
        rest = &after[end + 2..];
    }
    found
}

/// For a script that writes `$RELEASE_TAG_INPUT` to `$GITHUB_OUTPUT`, the tag
/// must first be matched against the SemVer pattern with a failing exit.
fn release_tag_validated_before_output(text: &str) -> bool {
    let Some(write) = text.find("\"$RELEASE_TAG_INPUT\" >> \"$GITHUB_OUTPUT\"") else {
        return true;
    };
    let Some(check) = text.find("\"$RELEASE_TAG_INPUT\" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+") else {
        return false;
    };
    let Some(exit) = text[check..].find("exit 1").map(|e| e + check) else {
        return false;
    };
    check < write && exit < write
}

fn workflows_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(".github")
        .join("workflows")
}

fn workflow_files() -> Vec<(String, String)> {
    let mut files: Vec<_> = std::fs::read_dir(workflows_dir())
        .expect("read .github/workflows")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml")))
        .map(|p| {
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let src = std::fs::read_to_string(&p).expect("read workflow");
            (name, src)
        })
        .collect();
    files.sort();
    files
}

#[test]
fn no_run_script_expands_a_caller_controlled_expression() {
    let files = workflow_files();
    assert!(!files.is_empty(), "no workflows found");
    let mut violations = Vec::new();
    for (name, src) in &files {
        for block in run_blocks(src) {
            for expr in untrusted_expressions(&block.text) {
                violations.push(format!("{name}:{} `${{{{ {expr} }}}}`", block.line));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "pass these through `env:` and reference the shell variable instead:\n{}",
        violations.join("\n")
    );
}

#[test]
fn release_workflows_validate_the_tag_input_before_using_it() {
    let files = workflow_files();
    for wanted in ["release.yml", "release-tier2.yml"] {
        let (_, src) = files
            .iter()
            .find(|(n, _)| n == wanted)
            .unwrap_or_else(|| panic!("{wanted} missing"));
        let blocks = run_blocks(src);
        let writers: Vec<_> = blocks
            .iter()
            .filter(|b| {
                b.text
                    .contains("\"$RELEASE_TAG_INPUT\" >> \"$GITHUB_OUTPUT\"")
            })
            .collect();
        assert!(
            !writers.is_empty(),
            "{wanted}: the release tag must reach $GITHUB_OUTPUT via the RELEASE_TAG_INPUT env var"
        );
        for b in writers {
            assert!(
                release_tag_validated_before_output(&b.text),
                "{wanted}:{}: release tag written to $GITHUB_OUTPUT without the SemVer check",
                b.line
            );
        }
    }
}

// ── negative controls: the scanner must fire on the shapes it forbids ──

#[test]
fn scanner_flags_block_and_inline_interpolation() {
    let wf = r#"
jobs:
  a:
    steps:
      - name: block
        run: |
          echo "tag=${{ github.event.inputs.release_tag }}" >> $GITHUB_OUTPUT
      - run: echo ${{ inputs.pr }}
      - name: head
        run: >
          git checkout ${{ github.head_ref }}
      - name: fine
        env:
          TAG: ${{ github.event.inputs.release_tag }}
        run: |
          echo "$TAG ${{ github.repository }} ${{ matrix.os }}"
"#;
    let flagged: Vec<String> = run_blocks(wf)
        .iter()
        .flat_map(|b| untrusted_expressions(&b.text))
        .collect();
    assert_eq!(
        flagged,
        vec![
            "github.event.inputs.release_tag".to_string(),
            "inputs.pr".to_string(),
            "github.head_ref".to_string(),
        ]
    );
}

#[test]
fn scanner_requires_tag_check_before_output() {
    let ok = r#"if [[ ! "$RELEASE_TAG_INPUT" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-x)?$ ]]; then
  exit 1
fi
printf 'tag=%s\n' "$RELEASE_TAG_INPUT" >> "$GITHUB_OUTPUT""#;
    assert!(release_tag_validated_before_output(ok));

    let unchecked = r#"printf 'tag=%s\n' "$RELEASE_TAG_INPUT" >> "$GITHUB_OUTPUT""#;
    assert!(!release_tag_validated_before_output(unchecked));

    let checked_after = r#"printf 'tag=%s\n' "$RELEASE_TAG_INPUT" >> "$GITHUB_OUTPUT"
if [[ ! "$RELEASE_TAG_INPUT" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then exit 1; fi"#;
    assert!(!release_tag_validated_before_output(checked_after));

    let no_exit = r#"if [[ ! "$RELEASE_TAG_INPUT" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo bad; fi
printf 'tag=%s\n' "$RELEASE_TAG_INPUT" >> "$GITHUB_OUTPUT""#;
    assert!(!release_tag_validated_before_output(no_exit));
}

//! Three-tiered mechanical code quality enforcement.
//!
//! This module implements a pragmatic, AST-based approach to automated code quality,
//! distinguishing between critical correctness issues and subjective style preferences.
//! It is designed to be robust, low-friction, and easy to maintain.
//!
//! ## Enforcement Philosophy: Context-Aware Quality
//!
//! This linter delegates where appropriate. It assumes `rustfmt --check` and
//! `cargo clippy` (with a configured cognitive_complexity_threshold) are run
//! separately in CI. This tool focuses on what those checkers cannot do.
//!
//! **Level 1: Critical Enforcement** (#[deny] - CI failures)
//! - Memory safety and panic prevention in production.
//! - Public API naming clarity for an unambiguous public contract.
//! - Architectural integrity (no anti-pattern modules like `utils.rs`).
//! - Consistent, structured error handling.
//! - Documentation for all public APIs.
//!
//! **Level 2: Quality Ratchets** (Prevent regression, allow conscious exceptions)
//! - Module size growth prevention using a high-water mark.
//! - Struct field count limits.
//!
//! **Level 3: Style Guidelines** (Human-centric, no CI failure)
//! - Internal naming conventions are left to professional judgment and code review.
//!   This is an explicit choice to trust developers and avoid noisy, restrictive rules.

use std::fs;
use std::path::{Path, PathBuf};

use proc_macro2::Span;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{FnArg, ItemFn, ItemStruct, Pat, PatType, Stmt, Visibility};
use walkdir;

// --- Configuration Constants ---

/// LEVEL 2 RATCHET: Max fields in any struct. Prevents structs from becoming bloated.
/// Current technical debt: Several protocol structs exceed this (up to 29 fields)
const STRUCT_FIELD_COUNT_MAX: usize = 30;

/// LEVEL 2 RATCHET: The current maximum number of lines for any single module.
/// Current technical debt: context.rs has grown to 1406 lines and needs refactoring
const MODULE_SIZE_HIGH_WATER_MARK: usize = 1410;

// --- Data Structures for Tidy Checks ---

/// The severity of a lint violation. Determines if it fails the build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    Guideline, // A suggestion, will be printed but will not fail CI.
    Ratchet,   // A regression against a quality metric. Fails CI.
    Critical,  // A direct violation of a core project rule. Fails CI.
}

/// A single violation found by the tidy linter.
#[derive(Debug)]
struct TidyViolation {
    severity: Severity,
    path: String,
    line: usize,
    message: String,
}

impl TidyViolation {
    fn new(severity: Severity, path: &Path, span: Span, message: impl Into<String>) -> Self {
        TidyViolation {
            severity,
            path: path.to_string_lossy().to_string(),
            line: span.start().line,
            message: message.into(),
        }
    }
}

/// Represents a source file being tidied.
struct SourceFile<'a> {
    path: &'a Path,
    text: &'a str,
}

// --- AST-Based Visitor for Code Analysis ---

/// An AST visitor that walks a `syn::File` and collects `TidyViolation`s.
/// This is the core of our robust, structure-aware linter.
struct TidyVisitor<'a> {
    file: &'a SourceFile<'a>,
    is_test_context: bool,
    violations: Vec<TidyViolation>,
}

impl<'a> TidyVisitor<'a> {
    fn new(file: &'a SourceFile<'a>) -> Self {
        let path_str = file.path.to_string_lossy();
        let is_test_context = path_str.contains("/tests/")
            || path_str.ends_with("_test.rs")
            || file.text.contains("#[cfg(test)]");

        Self {
            file,
            is_test_context,
            violations: Vec::new(),
        }
    }

    /// Central handler to add a new violation.
    fn add_violation(&mut self, severity: Severity, span: Span, message: impl Into<String>) {
        self.violations
            .push(TidyViolation::new(severity, self.file.path, span, message));
    }
}

impl<'ast, 'a> Visit<'ast> for TidyVisitor<'a> {
    /// Check function definitions for public API naming and documentation.
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        let is_public = matches!(item.vis, Visibility::Public(_));

        if is_public && !self.is_test_context {
            // LEVEL 1: Public functions must be documented.
            let has_doc = item.attrs.iter().any(|attr| attr.path().is_ident("doc"));
            if !has_doc {
                self.add_violation(
                    Severity::Critical,
                    item.sig.fn_token.span(),
                    format!(
                        "Public function '{}' must have documentation.",
                        item.sig.ident
                    ),
                );
            }

            // LEVEL 1: Public function names must not use abbreviations.
            let func_name = item.sig.ident.to_string();
            if func_name.contains("ctx") {
                self.add_violation(
                    Severity::Critical,
                    item.sig.ident.span(),
                    "Public API function name uses 'ctx'; prefer 'context'.",
                );
            }

            // LEVEL 1: Public function parameters must not use abbreviations.
            for arg in &item.sig.inputs {
                if let FnArg::Typed(PatType { pat, .. }) = arg {
                    if let Pat::Ident(pat_ident) = &**pat {
                        let param_name = pat_ident.ident.to_string();
                        if param_name == "ctx" {
                            self.add_violation(
                                Severity::Critical,
                                pat_ident.span(),
                                "Public API parameter 'ctx' must be named 'context'.",
                            );
                        }
                        if param_name == "seq_num" {
                            self.add_violation(
                                Severity::Critical,
                                pat_ident.span(),
                                "Public API parameter 'seq_num' must be named 'sequence_number'.",
                            );
                        }
                    }
                }
            }
        }

        // Continue traversal into the function body.
        visit::visit_item_fn(self, item);
    }

    /// Check struct definitions for field count and public API rules.
    fn visit_item_struct(&mut self, item: &'ast ItemStruct) {
        let is_public = matches!(item.vis, Visibility::Public(_));

        // LEVEL 2: Struct field count ratchet.
        if item.fields.len() > STRUCT_FIELD_COUNT_MAX {
            self.add_violation(
                Severity::Ratchet,
                item.ident.span(),
                format!(
                    "Struct '{}' has {} fields, exceeding the max of {}. Consider decomposition.",
                    item.ident,
                    item.fields.len(),
                    STRUCT_FIELD_COUNT_MAX
                ),
            );
        }

        if is_public && !self.is_test_context {
            // LEVEL 1: Public structs must be documented.
            let has_doc = item.attrs.iter().any(|attr| attr.path().is_ident("doc"));
            if !has_doc {
                self.add_violation(
                    Severity::Critical,
                    item.struct_token.span(),
                    format!("Public struct '{}' must have documentation.", item.ident),
                );
            }
        }

        visit::visit_item_struct(self, item);
    }

    /// Check statements for `.unwrap()` and `panic!` in production code.
    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        if !self.is_test_context {
            // LEVEL 1: Disallow .unwrap() and .expect()
            if let Some(span) = find_call_in_stmt(stmt, "unwrap") {
                // Check if this line has the safety comment
                let line_text = self
                    .file
                    .text
                    .lines()
                    .nth(span.start().line - 1)
                    .unwrap_or("");
                if !line_text.contains("// unwrap: safe because") {
                    self.add_violation(
                        Severity::Critical,
                        span,
                        "Do not use .unwrap() in production code; use proper error handling or document safety."
                    );
                }
            }

            if let Some(span) = find_call_in_stmt(stmt, "expect") {
                self.add_violation(
                    Severity::Critical,
                    span,
                    "Do not use .expect() in production code; use structured errors.",
                );
            }
        }

        visit::visit_stmt(self, stmt);
    }
}

/// Helper to find a specific method call within a statement's expression.
fn find_call_in_stmt(stmt: &Stmt, method_name: &str) -> Option<Span> {
    match stmt {
        Stmt::Expr(expr, _) => {
            if let syn::Expr::MethodCall(mc) = expr {
                if mc.method == method_name {
                    return Some(mc.method.span());
                }
            }
        }
        _ => {}
    }
    None
}

// --- Standalone Tidy Checks (No AST Required) ---

/// LEVEL 1: Checks for `FIXME` comments, which are not allowed in the main branch.
fn check_for_fixme(file: &SourceFile, violations: &mut Vec<TidyViolation>) {
    for (i, line) in file.text.lines().enumerate() {
        if line.contains("FIXME") {
            // We can't get a real Span here, so we create a placeholder.
            // This part of the code can be improved if more precise location is needed.
            let placeholder_span = Span::call_site();
            violations.push(TidyViolation::new(
                Severity::Critical,
                file.path,
                placeholder_span,
                format!(
                    "Line {}: FIXME comments are not allowed in the main branch.",
                    i + 1
                ),
            ));
        }
    }
}

// --- Main Test Suite ---

fn list_rust_files() -> Vec<PathBuf> {
    walkdir::WalkDir::new("src")
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_type().is_file() && e.path().extension().map_or(false, |ext| ext == "rs")
        })
        .map(|e| e.path().to_path_buf())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tidy_main() {
        let mut all_violations = Vec::new();
        let mut max_module_loc = 0;

        // --- Phase 1: File-by-file analysis ---
        for path in &list_rust_files() {
            if path.to_string_lossy().contains("tidy.rs") {
                continue;
            }

            let source_text = fs::read_to_string(&path).expect("Failed to read file");
            let file = SourceFile {
                path,
                text: &source_text,
            };
            let line_count = source_text.lines().count();

            if line_count > max_module_loc {
                max_module_loc = line_count;
            }

            // Run non-AST checks
            check_for_fixme(&file, &mut all_violations);
            // check_for_anti_pattern_modules is run once, below.

            // Run AST-based checks
            match syn::parse_file(&source_text) {
                Ok(ast) => {
                    let mut visitor = TidyVisitor::new(&file);
                    visitor.visit_file(&ast);
                    all_violations.extend(visitor.violations);
                }
                Err(e) => {
                    all_violations.push(TidyViolation::new(
                        Severity::Critical,
                        path,
                        e.span(),
                        format!("Failed to parse file: {}", e),
                    ));
                }
            }
        }

        // --- Phase 2: Project-wide and aggregate checks ---
        if let Err(e) = check_for_anti_pattern_modules() {
            all_violations.push(e);
        }

        // LEVEL 2: Module Size Ratchet
        if max_module_loc > MODULE_SIZE_HIGH_WATER_MARK {
            all_violations.push(TidyViolation {
                severity: Severity::Ratchet,
                path: "Project-wide".to_string(),
                line: 0,
                message: format!("A module has grown to {} lines, exceeding the high-water mark of {}. Justify and update the constant.", max_module_loc, MODULE_SIZE_HIGH_WATER_MARK),
            });
        }

        // --- Phase 3: Report results ---
        if all_violations.is_empty() {
            return; // Success!
        }

        // Sort for stable output
        all_violations.sort_by_key(|v| (v.severity, v.path.clone(), v.line));

        let guidelines: Vec<_> = all_violations
            .iter()
            .filter(|v| v.severity == Severity::Guideline)
            .collect();
        let failures: Vec<_> = all_violations
            .iter()
            .filter(|v| v.severity > Severity::Guideline)
            .collect();

        if !guidelines.is_empty() {
            eprintln!("\n--- Tidy Guidelines (Warnings) ---");
            for v in guidelines {
                eprintln!("[GUIDELINE] {}:{}: {}", v.path, v.line, v.message);
            }
        }

        if !failures.is_empty() {
            panic!(
                "\n--- Tidy Failures (Critical / Ratchet) ---\n{}\n",
                failures
                    .iter()
                    .map(|v| format!("[{:?}] {}:{}: {}", v.severity, v.path, v.line, v.message))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
    }

    /// LEVEL 1: Checks for anti-pattern module names like `utils.rs`.
    fn check_for_anti_pattern_modules() -> Result<(), TidyViolation> {
        const ANTI_PATTERNS: &[&str] = &["utils.rs", "helpers.rs", "misc.rs", "common.rs"];
        let walker = walkdir::WalkDir::new("src").into_iter();

        for entry in walker.filter_map(Result::ok) {
            let file_name = entry.file_name().to_string_lossy();
            if ANTI_PATTERNS.iter().any(|&p| p == file_name) {
                return Err(TidyViolation {
                    severity: Severity::Critical,
                    path: entry.path().display().to_string(),
                    line: 0,
                    message:
                        "Anti-pattern module name found. Use focused, descriptive module names."
                            .to_string(),
                });
            }
        }
        Ok(())
    }

    /// This test simply prints a report of what is being checked.
    #[test]
    fn tidy_coverage_report() {
        println!("\n--- Tidy Coverage Report ---");
        println!("This tidy linter mechanizes our style guide to ensure long-term code health.");
        println!("It assumes `rustfmt` and `clippy` are run separately in CI.\n");
        println!("ENFORCED RULES:");
        println!("  [CRITICAL] No `FIXME` comments in the main branch.");
        println!("  [CRITICAL] No `.unwrap()` or `.expect()` in production code.");
        println!("  [CRITICAL] No anti-pattern modules (e.g., `utils.rs`).");
        println!("  [CRITICAL] Public APIs must have documentation.");
        println!("  [CRITICAL] Public API names must be unambiguous (e.g., `context` not `ctx`).");
        println!(
            "  [RATCHET]  Module size must not exceed the high-water mark ({} lines).",
            MODULE_SIZE_HIGH_WATER_MARK
        );
        println!(
            "  [RATCHET]  Structs must not have more than {} fields.",
            STRUCT_FIELD_COUNT_MAX
        );
        println!("\nThis suite frees human reviewers to focus on logic and architecture.");
    }
}

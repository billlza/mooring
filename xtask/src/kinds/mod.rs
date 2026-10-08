// SPDX-License-Identifier: GPL-3.0-or-later

//! `kinds-coverage` (design §14): every variant of every public `Kind` enum
//! (`pub enum Kind` or `pub enum <Something>Kind`) in a crate's `src/` must be
//! named as `<Enum>::<Variant>` in that crate's test code.
//!
//! Test code is every file under `tests/`, every `#[cfg(test)]` item in
//! `src/`, and every file reached through a `#[cfg(test)] mod name;`
//! declaration (with its own submodules). A reference also counts through an
//! alias (`use crate::error::Kind as StoreKind;`). Glob imports followed by a
//! bare variant name, or iterating `Kind::ALL`, do not count: each variant
//! must be named.

mod lexer;
mod scan;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use crate::cargo::Cargo;
use crate::metadata::{self, MetadataError};
use crate::output::{OutputError, say};

use self::scan::{FileScan, ModDecl, ScanError};

#[derive(Debug, thiserror::Error)]
pub(crate) enum KindsError {
    #[error(transparent)]
    Metadata(#[from] MetadataError),
    #[error(transparent)]
    Output(#[from] OutputError),
    #[error("failed to read {}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{} is a symbolic link; only regular files and directories are scanned", path.display())]
    Symlink { path: PathBuf },
    #[error("{} is not a directory", path.display())]
    NotADirectory { path: PathBuf },
    #[error("cannot scan {}", path.display())]
    Scan {
        path: PathBuf,
        #[source]
        source: ScanError,
    },
    #[error("{}:{line}: no file for module `{module}`", file.display())]
    ModuleNotFound {
        file: PathBuf,
        module: String,
        line: u32,
    },
    #[error("{}:{line}: module `{module}` has both a `.rs` and a `mod.rs` file", file.display())]
    AmbiguousModule {
        file: PathBuf,
        module: String,
        line: u32,
    },
    #[error("{} has no parent directory or file stem", path.display())]
    BadModulePath { path: PathBuf },
    #[error("kinds-coverage found {0} Kind variant(s) that no test names")]
    Uncovered(usize),
}

/// The coverage of one `Kind` enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnumCoverage {
    pub(crate) file: PathBuf,
    pub(crate) name: String,
    pub(crate) line: u32,
    pub(crate) variants: usize,
    pub(crate) missing: Vec<String>,
}

pub(crate) fn run(cargo: &Cargo, out: &mut impl Write) -> Result<(), KindsError> {
    let metadata = metadata::load(cargo, &["--no-deps"])?;
    let mut enums = 0_usize;
    let mut variants = 0_usize;
    let mut uncovered = 0_usize;
    for package in metadata.members()? {
        let root = package.manifest_dir()?;
        let coverage = CrateSources::read(root)?.coverage()?;
        for item in &coverage {
            if !item.missing.is_empty() {
                say!(
                    out,
                    "kinds-coverage: {} {}:{}: {} not named by any test: {}",
                    package.name,
                    item.file.display(),
                    item.line,
                    item.name,
                    item.missing
                        .iter()
                        .map(|variant| format!("{}::{variant}", item.name))
                        .collect::<Vec<_>>()
                        .join(", ")
                )?;
            }
            variants += item.variants;
            uncovered += item.missing.len();
        }
        enums += coverage.len();
    }
    if uncovered == 0 {
        say!(
            out,
            "kinds-coverage: all {variants} variant(s) of {enums} Kind enum(s) are named by tests"
        )?;
        Ok(())
    } else {
        Err(KindsError::Uncovered(uncovered))
    }
}

/// The scanned `src/` and `tests/` files of one crate.
#[derive(Debug)]
pub(crate) struct CrateSources {
    src_dir: PathBuf,
    src: BTreeMap<PathBuf, FileScan>,
    tests: BTreeMap<PathBuf, FileScan>,
}

impl CrateSources {
    fn read(root: &Path) -> Result<Self, KindsError> {
        let src_dir = root.join("src");
        let src = scan_tree(&src_dir)?;
        let tests_dir = root.join("tests");
        let tests = match fs::symlink_metadata(&tests_dir) {
            Ok(_) => scan_tree(&tests_dir)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(source) => {
                return Err(KindsError::Read {
                    path: tests_dir,
                    source,
                });
            }
        };
        Ok(Self {
            src_dir,
            src,
            tests,
        })
    }

    /// One entry per non-test `Kind` enum in `src/`, in file order.
    pub(crate) fn coverage(&self) -> Result<Vec<EnumCoverage>, KindsError> {
        let test_files = self.test_module_files()?;
        let in_test = |path: &Path, flagged: bool| flagged || test_files.contains(path);

        let referenced: BTreeSet<(&str, &str)> = self
            .tests
            .values()
            .flat_map(|scan| &scan.paths)
            .chain(self.src.iter().flat_map(|(path, scan)| {
                scan.paths
                    .iter()
                    .filter(move |reference| in_test(path, reference.in_test))
            }))
            .map(|reference| (reference.head.as_str(), reference.tail.as_str()))
            .collect();
        let aliases: Vec<(&str, &str)> = self
            .src
            .values()
            .chain(self.tests.values())
            .flat_map(|scan| &scan.aliases)
            .map(|alias| (alias.original.as_str(), alias.alias.as_str()))
            .collect();

        let mut coverage = Vec::new();
        for (path, scan) in &self.src {
            for kind in scan
                .kind_enums
                .iter()
                .filter(|kind| !in_test(path, kind.in_test))
            {
                let names = alias_closure(&kind.name, &aliases);
                let missing = kind
                    .variants
                    .iter()
                    .filter(|variant| {
                        !names
                            .iter()
                            .any(|name| referenced.contains(&(name, variant.as_str())))
                    })
                    .cloned()
                    .collect();
                coverage.push(EnumCoverage {
                    file: path.clone(),
                    name: kind.name.clone(),
                    line: kind.line,
                    variants: kind.variants.len(),
                    missing,
                });
            }
        }
        Ok(coverage)
    }

    /// Files in `src/` that are test-only as a whole: `#![cfg(test)]` files,
    /// files declared by a test-only `mod name;`, and their submodules. (A
    /// test module may also live under `tests/`, which is test code anyway.)
    fn test_module_files(&self) -> Result<BTreeSet<PathBuf>, KindsError> {
        let mut pending: Vec<PathBuf> = self
            .src
            .iter()
            .filter(|(_, scan)| scan.file_is_test)
            .map(|(path, _)| path.clone())
            .collect();
        for (path, scan) in &self.src {
            for decl in scan.mod_decls.iter().filter(|decl| decl.in_test) {
                pending.push(self.resolve(path, decl)?);
            }
        }
        let mut test_files = BTreeSet::new();
        while let Some(path) = pending.pop() {
            if let Some(scan) = self.src.get(&path)
                && test_files.insert(path.clone())
            {
                for decl in &scan.mod_decls {
                    pending.push(self.resolve(&path, decl)?);
                }
            }
        }
        Ok(test_files)
    }

    /// The file that `decl`, written in `file`, loads (Rust reference, "Modules").
    fn resolve(&self, file: &Path, decl: &ModDecl) -> Result<PathBuf, KindsError> {
        let bad_path = || KindsError::BadModulePath {
            path: file.to_path_buf(),
        };
        let file_dir = file.parent().ok_or_else(bad_path)?;
        let is_mod_rs = matches!(
            file.file_name().and_then(|name| name.to_str()),
            Some("lib.rs" | "main.rs" | "mod.rs")
        ) || file_dir == self.src_dir.join("bin");
        let module_dir = if is_mod_rs {
            file_dir.to_path_buf()
        } else {
            file_dir.join(file.file_stem().ok_or_else(bad_path)?)
        };
        let nested = decl
            .inline_path
            .iter()
            .fold(module_dir, |dir, inline| dir.join(inline));
        let candidates = match &decl.path_attr {
            Some(path) if decl.inline_path.is_empty() => vec![file_dir.join(path)],
            Some(path) => vec![nested.join(path)],
            None => vec![
                nested.join(format!("{}.rs", decl.name)),
                nested.join(&decl.name).join("mod.rs"),
            ],
        };
        let found: Vec<PathBuf> = candidates
            .iter()
            .map(|candidate| normalize(candidate))
            .filter(|candidate| {
                self.src.contains_key(candidate) || self.tests.contains_key(candidate)
            })
            .collect();
        match found.as_slice() {
            [one] => Ok(one.clone()),
            [] => Err(KindsError::ModuleNotFound {
                file: file.to_path_buf(),
                module: decl.name.clone(),
                line: decl.line,
            }),
            _ => Err(KindsError::AmbiguousModule {
                file: file.to_path_buf(),
                module: decl.name.clone(),
                line: decl.line,
            }),
        }
    }
}

/// `name` and every name reachable from it through `original as alias` pairs.
fn alias_closure<'a>(name: &'a str, aliases: &[(&'a str, &'a str)]) -> BTreeSet<&'a str> {
    let mut names = BTreeSet::from([name]);
    let mut pending = vec![name];
    while let Some(current) = pending.pop() {
        for &(original, alias) in aliases {
            if original == current && names.insert(alias) {
                pending.push(alias);
            }
        }
    }
    names
}

/// Resolves `.` and `..` lexically, as `#[path]` attributes are joined textually.
fn normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other),
        }
    }
    normalized
}

/// Scans every `.rs` file below `dir`.
fn scan_tree(dir: &Path) -> Result<BTreeMap<PathBuf, FileScan>, KindsError> {
    let mut files = Vec::new();
    collect_rust_files(dir, &mut files)?;
    files
        .into_iter()
        .map(|path| {
            let source = fs::read_to_string(&path).map_err(|source| KindsError::Read {
                path: path.clone(),
                source,
            })?;
            let scanned = scan::scan(&source).map_err(|source| KindsError::Scan {
                path: path.clone(),
                source,
            })?;
            Ok((path, scanned))
        })
        .collect()
}

fn collect_rust_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), KindsError> {
    let read_error = |source| KindsError::Read {
        path: dir.to_path_buf(),
        source,
    };
    let file_type = fs::symlink_metadata(dir).map_err(read_error)?.file_type();
    if file_type.is_symlink() {
        return Err(KindsError::Symlink {
            path: dir.to_path_buf(),
        });
    }
    if !file_type.is_dir() {
        return Err(KindsError::NotADirectory {
            path: dir.to_path_buf(),
        });
    }
    for entry in fs::read_dir(dir).map_err(read_error)? {
        let entry = entry.map_err(read_error)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| KindsError::Read {
            path: path.clone(),
            source,
        })?;
        if file_type.is_symlink() {
            return Err(KindsError::Symlink { path });
        }
        if file_type.is_dir() {
            collect_rust_files(&path, files)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use super::{CrateSources, EnumCoverage, KindsError, alias_closure, normalize, scan};

    fn sources(src: &[(&str, &str)], tests: &[(&str, &str)]) -> CrateSources {
        let scan_all = |files: &[(&str, &str)], dir: &str| -> BTreeMap<PathBuf, scan::FileScan> {
            files
                .iter()
                .map(|(name, source)| {
                    (
                        Path::new("/c").join(dir).join(name),
                        scan::scan(source).unwrap(),
                    )
                })
                .collect()
        };
        CrateSources {
            src_dir: PathBuf::from("/c/src"),
            src: scan_all(src, "src"),
            tests: scan_all(tests, "tests"),
        }
    }

    fn missing(coverage: &[EnumCoverage]) -> Vec<(String, Vec<String>)> {
        coverage
            .iter()
            .map(|item| (item.name.clone(), item.missing.clone()))
            .collect()
    }

    fn owned(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    const ERROR_RS: &str = "pub enum Kind { Entropy, CertBuild, Lock }";

    #[test]
    fn a_crate_without_kind_enums_passes() {
        let crate_sources = sources(&[("lib.rs", "pub fn f() {}")], &[]);
        assert_eq!(crate_sources.coverage().unwrap(), []);
    }

    #[test]
    fn counts_references_from_integration_tests_and_cfg_test_modules_only() {
        let lib = "
            pub mod error;
            pub fn production() -> error::Kind { error::Kind::Lock }
            #[cfg(test)]
            mod tests { #[test] fn t() { assert_eq!(f(), crate::error::Kind::Entropy); } }
        ";
        let integration = "#[test] fn t() { let _ = mooring_x::error::Kind::CertBuild; }";
        let crate_sources = sources(
            &[("lib.rs", lib), ("error.rs", ERROR_RS)],
            &[("it.rs", integration)],
        );
        let coverage = crate_sources.coverage().unwrap();
        assert_eq!(
            coverage,
            [EnumCoverage {
                file: PathBuf::from("/c/src/error.rs"),
                name: "Kind".to_owned(),
                line: 1,
                variants: 3,
                missing: owned(&["Lock"]),
            }]
        );
    }

    #[test]
    fn follows_out_of_line_test_modules_and_their_submodules() {
        let lib = "pub mod error;\n#[cfg(test)]\nmod tests;";
        let tests_mod = "mod helpers;\n#[test] fn t() { Kind::Entropy; }";
        let helpers = "fn h() { Kind::CertBuild; Kind::Lock; }";
        let crate_sources = sources(
            &[
                ("lib.rs", lib),
                ("error.rs", ERROR_RS),
                ("tests/mod.rs", tests_mod),
                ("tests/helpers.rs", helpers),
            ],
            &[],
        );
        assert_eq!(
            missing(&crate_sources.coverage().unwrap()),
            [("Kind".to_owned(), vec![])]
        );
    }

    #[test]
    fn resolves_non_mod_rs_parents_and_path_attributes() {
        let error = "pub enum Kind { A, B }\n#[cfg(test)]\nmod tests;\n#[cfg(test)]\n#[path = \"nested/../extra_tests.rs\"]\nmod extra;";
        let crate_sources = sources(
            &[
                ("lib.rs", "pub mod error;"),
                ("error.rs", error),
                ("error/tests.rs", "fn t() { Kind::A; }"),
                ("extra_tests.rs", "fn t() { Kind::B; }"),
            ],
            &[],
        );
        assert_eq!(
            missing(&crate_sources.coverage().unwrap()),
            [("Kind".to_owned(), vec![])]
        );
    }

    #[test]
    fn a_test_module_may_live_under_the_tests_directory() {
        let lib =
            "pub enum Kind { A }\n#[cfg(test)]\n#[path = \"../tests/common/mod.rs\"]\nmod common;";
        let crate_sources = sources(
            &[("lib.rs", lib)],
            &[("common/mod.rs", "pub fn c() { crate::Kind::A; }")],
        );
        assert_eq!(
            missing(&crate_sources.coverage().unwrap()),
            [("Kind".to_owned(), vec![])]
        );
    }

    #[test]
    fn production_only_modules_do_not_count() {
        let lib = "pub mod error;\nmod helpers;";
        let crate_sources = sources(
            &[
                ("lib.rs", lib),
                ("error.rs", ERROR_RS),
                (
                    "helpers.rs",
                    "fn h() { Kind::Entropy; Kind::CertBuild; Kind::Lock; }",
                ),
            ],
            &[],
        );
        assert_eq!(
            missing(&crate_sources.coverage().unwrap()),
            [("Kind".to_owned(), owned(&["Entropy", "CertBuild", "Lock"]))]
        );
    }

    #[test]
    fn references_through_aliases_count_and_other_enums_do_not() {
        let lib =
            "pub mod error;\npub use error::Kind as StoreKind;\npub enum OtherKind { Entropy }";
        let integration = "use mooring_x::StoreKind as K;\n#[test] fn t() { K::Entropy; StoreKind::CertBuild; OtherKind::Entropy; Kind2::Lock; }";
        let crate_sources = sources(
            &[("lib.rs", lib), ("error.rs", ERROR_RS)],
            &[("it.rs", integration)],
        );
        assert_eq!(
            missing(&crate_sources.coverage().unwrap()),
            [
                ("Kind".to_owned(), owned(&["Lock"])),
                ("OtherKind".to_owned(), vec![]),
            ]
        );
    }

    #[test]
    fn kind_enums_inside_test_code_are_not_checked() {
        let lib = "#[cfg(test)]\nmod tests;";
        let crate_sources = sources(
            &[("lib.rs", lib), ("tests.rs", "pub enum Kind { Fixture }")],
            &[("it.rs", "pub enum Kind { AlsoFixture }")],
        );
        assert_eq!(crate_sources.coverage().unwrap(), []);
    }

    #[test]
    fn a_missing_test_module_file_is_an_error() {
        let crate_sources = sources(&[("lib.rs", "#[cfg(test)]\nmod tests;")], &[]);
        assert!(matches!(
            crate_sources.coverage(),
            Err(KindsError::ModuleNotFound { module, line: 2, .. }) if module == "tests"
        ));
    }

    #[test]
    fn an_ambiguous_test_module_file_is_an_error() {
        let crate_sources = sources(
            &[
                ("lib.rs", "#[cfg(test)]\nmod tests;"),
                ("tests.rs", ""),
                ("tests/mod.rs", ""),
            ],
            &[],
        );
        assert!(matches!(
            crate_sources.coverage(),
            Err(KindsError::AmbiguousModule { module, .. }) if module == "tests"
        ));
    }

    #[test]
    fn alias_closure_is_transitive() {
        let aliases = [("Kind", "A"), ("A", "B"), ("Other", "C")];
        assert_eq!(
            alias_closure("Kind", &aliases)
                .into_iter()
                .collect::<Vec<_>>(),
            ["A", "B", "Kind"]
        );
    }

    #[test]
    fn normalize_resolves_parent_components() {
        assert_eq!(
            normalize(Path::new("/c/src/error/../extra_tests.rs")),
            PathBuf::from("/c/src/extra_tests.rs")
        );
    }
}

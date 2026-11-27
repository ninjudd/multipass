//! `multipass upgrade`, which downloads the released installer with `curl`,
//! checks its attestation with `gh` when `gh` is installed, and runs it.
//!
//! multipass has no network code of its own: `curl` and `bash` are external
//! programs at fixed paths, as `/bin/stty` is for the passphrase prompt, and
//! nothing here runs unless you type `upgrade`. The installer then does what
//! it does for `curl | bash`, so an upgrade gets exactly the installer's
//! checks. docs/projects/installer/readme.md § 2.3 is the design.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// The repository whose release workflow must have built the installer.
const REPO: &str = "ninjudd/multipass";

/// Exit statuses, from sysexits.h, matching the installer's.
const EX_DATAERR: u8 = 65;
const EX_UNAVAILABLE: u8 = 69;

/// The programs and places `upgrade` uses. `main` passes the fixed paths and
/// the real URLs; tests pass fake programs in a temporary directory.
pub struct Tools {
    pub curl: PathBuf,
    pub bash: PathBuf,
    /// `gh` when it is on PATH; without it the installer runs unchecked.
    pub gh: Option<PathBuf>,
    /// Where `install.sh` is served, such as `https://getmultipass.dev`.
    pub installer_url: String,
    /// The repository's releases, such as
    /// `https://github.com/ninjudd/multipass/releases`.
    pub releases_url: String,
    /// The installer's receipt, which records what it installed.
    pub receipt: PathBuf,
    /// The running executable, which the receipt must name.
    pub exe: PathBuf,
    /// The directory to make the private download directory in.
    pub temp: PathBuf,
}

impl Tools {
    /// The real programs and URLs, and the receipt where the installer
    /// writes it: `${XDG_DATA_HOME:-$HOME/.local/share}/multipass-install`.
    pub fn system() -> Result<Tools, Failure> {
        let data = match std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
            Some(dir) => PathBuf::from(dir),
            None => PathBuf::from(
                std::env::var_os("HOME").ok_or_else(|| unavailable("HOME is not set"))?,
            )
            .join(".local/share"),
        };
        Ok(Tools {
            curl: "/usr/bin/curl".into(),
            bash: "/bin/bash".into(),
            gh: find_on_path("gh", std::env::var_os("PATH").as_deref()),
            installer_url: "https://getmultipass.dev".into(),
            releases_url: format!("https://github.com/{REPO}/releases"),
            receipt: data.join("multipass-install").join("receipt"),
            exe: std::env::current_exe()
                .map_err(|e| unavailable(&format!("cannot tell which file is running: {e}")))?,
            temp: std::env::temp_dir(),
        })
    }
}

/// A failure, with the exit status the program ends with.
#[derive(Debug, PartialEq)]
pub struct Failure {
    pub status: u8,
    pub message: String,
}

fn unavailable(message: &str) -> Failure {
    Failure {
        status: EX_UNAVAILABLE,
        message: message.into(),
    }
}

/// Returns a release version without its leading `v`, or an error when it
/// is not one, so a version never puts anything else into a URL.
pub fn release_version(text: &str) -> Result<String, String> {
    let version = text.strip_prefix('v').unwrap_or(text);
    let (numbers, pre) = match version.split_once('-') {
        Some((numbers, pre)) => (numbers, Some(pre)),
        None => (version, None),
    };
    let numeric = numbers.split('.').count() == 3
        && numbers
            .split('.')
            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    let pre_ok = pre
        .is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.'));
    if numeric && pre_ok {
        Ok(version.to_string())
    } else {
        Err(format!("{text} is not a release version such as 0.2.0"))
    }
}

/// Runs the installer for `version`, or for the newest release, into the
/// directory the receipt names, and returns the installer's exit status.
pub fn upgrade(tools: &Tools, version: Option<&str>) -> Result<u8, Failure> {
    let bin_dir = installed_dir(tools)?;
    let work = WorkDir::new(&tools.temp)?;
    let script = work.path.join("install.sh");
    let installer = match version {
        Some(v) => format!("{}/v{v}/install.sh", tools.installer_url),
        None => format!("{}/install.sh", tools.installer_url),
    };
    download(tools, &installer, &script)?;

    match &tools.gh {
        Some(gh) => {
            let bundle = match version {
                Some(v) => format!(
                    "{}/download/v{v}/multipass.sigstore.json",
                    tools.releases_url
                ),
                None => format!(
                    "{}/latest/download/multipass.sigstore.json",
                    tools.releases_url
                ),
            };
            download(tools, &bundle, &work.path.join("multipass.sigstore.json"))?;
            let verified = Command::new(gh)
                .args(["attestation", "verify", "install.sh"])
                .args(["--bundle", "multipass.sigstore.json", "--repo", REPO])
                .arg("--signer-workflow")
                .arg(format!("{REPO}/.github/workflows/release.yml"))
                .args([
                    "--source-ref",
                    "refs/heads/main",
                    "--deny-self-hosted-runners",
                ])
                .current_dir(&work.path)
                .stdout(Stdio::null())
                .status()
                .map_err(|e| unavailable(&format!("could not run {}: {e}", gh.display())))?;
            if !verified.success() {
                return Err(Failure {
                    status: EX_DATAERR,
                    message: format!(
                        "gh attestation verify rejected the installer from {installer}, so the release workflow did not build it; nothing was run"
                    ),
                });
            }
        }
        None => eprintln!("multipass: running the installer unchecked, as curl | bash would"),
    }

    let mut install = Command::new(&tools.bash);
    install
        .arg("install.sh")
        .current_dir(&work.path)
        .env("MULTIPASS_BIN_DIR", bin_dir);
    if let Some(v) = version {
        install.env("MULTIPASS_VERSION", v);
    }
    let status = install
        .status()
        .map_err(|e| unavailable(&format!("could not run {}: {e}", tools.bash.display())))?;
    // A signal leaves no exit code; report it as a plain failure.
    Ok(status.code().map_or(1, |code| code.clamp(0, 255) as u8))
}

/// Reads the newest release from where GitHub's `releases/latest` redirects,
/// and returns the exit status and the message to print: 0 when `current` is
/// the newest release or newer, and 1 when a newer release is out.
pub fn check(tools: &Tools, current: &str) -> Result<(u8, String), Failure> {
    let url = format!("{}/latest", tools.releases_url);
    let failed = || unavailable(&format!("could not read the newest release from {url}"));
    let output = Command::new(&tools.curl)
        .args(["-fsSI", "--proto", "=https"])
        .arg(&url)
        .stderr(Stdio::inherit())
        .output()
        .map_err(|_| failed())?;
    if !output.status.success() {
        return Err(failed());
    }
    let headers = String::from_utf8_lossy(&output.stdout);
    let newest = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("location"))
        .find_map(|(_, value)| value.trim().split_once("/releases/tag/"))
        .and_then(|(_, tag)| release_version(tag).ok())
        .ok_or_else(failed)?;
    Ok(match compare(&newest, current) {
        std::cmp::Ordering::Equal => (0, format!("multipass {current} is the newest release")),
        std::cmp::Ordering::Greater => (
            1,
            format!("multipass {newest} is out, and this is {current} -- run multipass upgrade"),
        ),
        std::cmp::Ordering::Less => (
            0,
            format!("multipass {current} is newer than the newest release, {newest}"),
        ),
    })
}

/// Orders two release versions as SemVer does. Their numbers decide first.
/// With the same numbers, a version with a suffix, such as `1.0.0-rc.1`, is
/// a prerelease and comes before the version without one. Two suffixes
/// compare part by part between the dots: numeric parts by value and before
/// any other part, other parts by text, and a suffix that runs out first
/// comes first.
fn compare(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    // Number sorts before Text because it is declared first.
    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    enum Part<'a> {
        Number(u64),
        Text(&'a str),
    }
    fn parts(text: &str) -> Vec<Part<'_>> {
        text.split('.')
            .map(|p| p.parse().map_or(Part::Text(p), Part::Number))
            .collect()
    }
    fn split(version: &str) -> (Vec<Part<'_>>, Option<Vec<Part<'_>>>) {
        match version.split_once('-') {
            Some((numbers, pre)) => (parts(numbers), Some(parts(pre))),
            None => (parts(version), None),
        }
    }
    let ((a_numbers, a_pre), (b_numbers, b_pre)) = (split(a), split(b));
    a_numbers
        .cmp(&b_numbers)
        .then_with(|| match (a_pre, b_pre) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a_pre), Some(b_pre)) => a_pre.cmp(&b_pre),
        })
}

/// Returns the directory the installer installed this executable into, or
/// refuses when the installer did not install it, so `upgrade` never writes
/// a second copy that the running one then shadows.
fn installed_dir(tools: &Tools) -> Result<PathBuf, Failure> {
    let not_ours = || {
        unavailable(&format!(
            "this multipass was not installed by the installer (it is {}); upgrade it the way you installed it, or run the installer",
            tools.exe.display()
        ))
    };
    let receipt = fs::read_to_string(&tools.receipt).map_err(|_| not_ours())?;
    let field = |key: &str| {
        receipt.lines().find_map(|line| {
            line.split_once(' ')
                .filter(|(k, _)| *k == key)
                .map(|(_, v)| v)
        })
    };
    let path = PathBuf::from(field("path").ok_or_else(not_ours)?);
    let same = match (fs::canonicalize(&path), fs::canonicalize(&tools.exe)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if !same {
        return Err(not_ours());
    }
    if field("method") == Some("checkout") {
        return Err(unavailable(&format!(
            "this multipass was built from the checkout at {}; pull it and run ./install.sh there",
            field("source").unwrap_or("its checkout")
        )));
    }
    path.parent().map(Path::to_path_buf).ok_or_else(not_ours)
}

fn download(tools: &Tools, url: &str, to: &Path) -> Result<(), Failure> {
    let status = Command::new(&tools.curl)
        .args(["-fsSL", "--proto", "=https", "-o"])
        .arg(to)
        .arg(url)
        .status()
        .map_err(|e| unavailable(&format!("could not run {}: {e}", tools.curl.display())))?;
    if status.success() {
        Ok(())
    } else {
        Err(unavailable(&format!("could not download {url}")))
    }
}

/// Finds an executable on a PATH-style list of directories.
fn find_on_path(name: &str, path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    std::env::split_paths(path?)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|file| {
            fs::metadata(file).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
}

/// A new directory only this user can read, removed when dropped. Creating
/// it fails rather than reusing a directory that already exists, so nobody
/// else can have put a file in it.
struct WorkDir {
    path: PathBuf,
}

impl WorkDir {
    fn new(parent: &Path) -> Result<WorkDir, Failure> {
        use std::os::unix::fs::DirBuilderExt;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let path = parent.join(format!("multipass-upgrade.{}.{nanos}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| {
                unavailable(&format!(
                    "could not create a temporary directory in {}: {e}",
                    parent.display()
                ))
            })?;
        Ok(WorkDir { path })
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A temporary directory holding fake `curl`, `gh`, and `bash` scripts
    /// that record what they were asked to do in `log`.
    struct Fake {
        dir: PathBuf,
        tools: Tools,
    }

    impl Fake {
        /// `gh` is `Some(status)` for a fake `gh` that exits with it.
        fn new(gh: Option<u8>) -> Fake {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "multipass-upgrade-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(dir.join("bin")).unwrap();
            fs::create_dir_all(dir.join("tmp")).unwrap();
            let log = dir.join("log");
            // The fake curl writes the URL it was given into the file after
            // -o, or prints a redirect for -I, as GitHub's releases/latest
            // answers, to the tag in the file `latest`.
            let latest = dir.join("latest");
            fs::write(&latest, "v0.3.0").unwrap();
            script(
                &dir.join("curl"),
                &format!(
                    r#"echo "curl $*" >> {log}
out=""; head=""
while [ $# -gt 1 ]; do
  case "$1" in -o) out="$2"; shift ;; -fsSI) head=1 ;; esac
  shift
done
if [ -n "$head" ]; then
  printf 'HTTP/2 302\r\nLocation: https://github.com/ninjudd/multipass/releases/tag/%s\r\n\r\n' "$(cat {latest})"
  exit 0
fi
case "$1" in *fail*) exit 22 ;; esac
echo "$1" > "$out""#,
                    log = log.display(),
                    latest = latest.display(),
                ),
            );
            if let Some(status) = gh {
                script(
                    &dir.join("gh"),
                    &format!(
                        "echo \"gh $* in $(pwd)\" >> {}\nexit {status}",
                        log.display()
                    ),
                );
            }
            script(
                &dir.join("bash"),
                &format!(
                    "echo \"bash $* from $(cat \"$1\") MULTIPASS_VERSION=${{MULTIPASS_VERSION:-}} MULTIPASS_BIN_DIR=$MULTIPASS_BIN_DIR\" >> {}\nexit 7",
                    log.display()
                ),
            );
            let exe = dir.join("bin").join("multipass");
            fs::write(&exe, "").unwrap();
            let receipt = dir.join("receipt");
            fs::write(
                &receipt,
                format!(
                    "version 0.2.0\nmethod binary\npath {}\nsha256 x\n",
                    exe.display()
                ),
            )
            .unwrap();
            let tools = Tools {
                curl: dir.join("curl"),
                bash: dir.join("bash"),
                gh: gh.map(|_| dir.join("gh")),
                installer_url: "https://getmultipass.dev".into(),
                releases_url: "https://github.com/ninjudd/multipass/releases".into(),
                receipt,
                exe,
                temp: dir.join("tmp"),
            };
            Fake { dir, tools }
        }

        fn log(&self) -> String {
            fs::read_to_string(self.dir.join("log")).unwrap_or_default()
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn script(path: &Path, body: &str) {
        fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn runs_the_checked_installer_and_passes_its_status_through() {
        let fake = Fake::new(Some(0));
        assert_eq!(upgrade(&fake.tools, None), Ok(7));
        let log = fake.log();
        assert!(log.contains("https://getmultipass.dev/install.sh"), "{log}");
        assert!(
            log.contains("https://github.com/ninjudd/multipass/releases/latest/download/multipass.sigstore.json"),
            "{log}"
        );
        assert!(
            log.contains("gh attestation verify install.sh --bundle multipass.sigstore.json --repo ninjudd/multipass --signer-workflow ninjudd/multipass/.github/workflows/release.yml --source-ref refs/heads/main --deny-self-hosted-runners"),
            "{log}"
        );
        let bin_dir = fake.dir.join("bin");
        assert!(
            log.contains(&format!(
                "bash install.sh from https://getmultipass.dev/install.sh MULTIPASS_VERSION= MULTIPASS_BIN_DIR={}",
                bin_dir.display()
            )),
            "{log}"
        );
        // The private download directory is gone afterwards.
        assert_eq!(fs::read_dir(&fake.tools.temp).unwrap().count(), 0);
    }

    #[test]
    fn a_named_version_reaches_the_urls_and_the_installer() {
        let fake = Fake::new(Some(0));
        assert_eq!(upgrade(&fake.tools, Some("0.2.0")), Ok(7));
        let log = fake.log();
        assert!(
            log.contains("https://getmultipass.dev/v0.2.0/install.sh"),
            "{log}"
        );
        assert!(
            log.contains("https://github.com/ninjudd/multipass/releases/download/v0.2.0/multipass.sigstore.json"),
            "{log}"
        );
        assert!(log.contains("MULTIPASS_VERSION=0.2.0 "), "{log}");
    }

    #[test]
    fn a_failed_attestation_stops_before_the_installer_runs() {
        let fake = Fake::new(Some(1));
        let failure = upgrade(&fake.tools, None).unwrap_err();
        assert_eq!(failure.status, EX_DATAERR);
        assert!(
            failure.message.contains("nothing was run"),
            "{}",
            failure.message
        );
        assert!(!fake.log().contains("bash "), "{}", fake.log());
        assert_eq!(fs::read_dir(&fake.tools.temp).unwrap().count(), 0);
    }

    #[test]
    fn runs_unchecked_without_gh() {
        let fake = Fake::new(None);
        assert_eq!(upgrade(&fake.tools, None), Ok(7));
        let log = fake.log();
        assert!(!log.contains("sigstore"), "{log}");
        assert!(log.contains("bash install.sh"), "{log}");
    }

    #[test]
    fn a_failed_download_runs_nothing() {
        let mut fake = Fake::new(Some(0));
        fake.tools.installer_url = "https://fail.example".into();
        assert_eq!(
            upgrade(&fake.tools, None).unwrap_err().status,
            EX_UNAVAILABLE
        );
        assert!(!fake.log().contains("gh "), "{}", fake.log());
        assert!(!fake.log().contains("bash "), "{}", fake.log());
    }

    #[test]
    fn refuses_a_multipass_the_installer_did_not_install() {
        // No receipt.
        let fake = Fake::new(Some(0));
        fs::remove_file(&fake.tools.receipt).unwrap();
        let failure = upgrade(&fake.tools, None).unwrap_err();
        assert_eq!(failure.status, EX_UNAVAILABLE);
        assert!(
            failure
                .message
                .starts_with("this multipass was not installed by the installer (it is "),
            "{}",
            failure.message
        );
        assert_eq!(fake.log(), "");

        // A receipt naming another file, such as one from cargo install
        // running beside an installed copy.
        let mut fake = Fake::new(Some(0));
        let other = fake.dir.join("cargo-multipass");
        fs::write(&other, "").unwrap();
        fake.tools.exe = other;
        assert_eq!(
            upgrade(&fake.tools, None).unwrap_err().status,
            EX_UNAVAILABLE
        );
        assert_eq!(fake.log(), "");

        // A checkout install upgrades by pulling the checkout.
        let fake = Fake::new(Some(0));
        fs::write(
            &fake.tools.receipt,
            format!(
                "method checkout\npath {}\nsource /src/multipass\n",
                fake.tools.exe.display()
            ),
        )
        .unwrap();
        let failure = upgrade(&fake.tools, None).unwrap_err();
        assert_eq!(failure.status, EX_UNAVAILABLE);
        assert!(
            failure.message.contains("/src/multipass"),
            "{}",
            failure.message
        );
        assert_eq!(fake.log(), "");
    }

    #[test]
    fn check_reads_the_newest_release_from_the_redirect() {
        let fake = Fake::new(None);
        assert_eq!(
            check(&fake.tools, "0.2.0"),
            Ok((
                1,
                "multipass 0.3.0 is out, and this is 0.2.0 -- run multipass upgrade".into()
            ))
        );
        assert_eq!(
            check(&fake.tools, "0.3.0"),
            Ok((0, "multipass 0.3.0 is the newest release".into()))
        );
        assert_eq!(
            check(&fake.tools, "0.10.0"),
            Ok((
                0,
                "multipass 0.10.0 is newer than the newest release, 0.3.0".into()
            ))
        );
        assert!(fake.log().contains(
            "curl -fsSI --proto =https https://github.com/ninjudd/multipass/releases/latest"
        ));
        assert!(!fake.log().contains("bash"));

        // A prerelease is older than the release with its numbers.
        fs::write(fake.dir.join("latest"), "v1.0.0").unwrap();
        assert_eq!(
            check(&fake.tools, "1.0.0-rc.1"),
            Ok((
                1,
                "multipass 1.0.0 is out, and this is 1.0.0-rc.1 -- run multipass upgrade".into()
            ))
        );
        fs::write(fake.dir.join("latest"), "v1.0.0-rc.10").unwrap();
        assert_eq!(
            check(&fake.tools, "1.0.0-rc.2"),
            Ok((
                1,
                "multipass 1.0.0-rc.10 is out, and this is 1.0.0-rc.2 -- run multipass upgrade"
                    .into()
            ))
        );
    }

    #[test]
    fn orders_versions_as_semver_does() {
        // SemVer 2.0.0's own example of precedence, § 11.4, plus a release
        // with larger numbers and a numeric part past 9.
        let ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.10.0",
        ];
        for (i, a) in ordered.iter().enumerate() {
            for (j, b) in ordered.iter().enumerate() {
                assert_eq!(compare(a, b), i.cmp(&j), "{a} against {b}");
            }
        }
    }

    #[test]
    fn accepts_only_release_versions() {
        assert_eq!(release_version("0.2.0"), Ok("0.2.0".into()));
        assert_eq!(release_version("v0.2.0"), Ok("0.2.0".into()));
        assert_eq!(release_version("1.0.0-rc.1"), Ok("1.0.0-rc.1".into()));
        for bad in [
            "",
            "v",
            "0.2",
            "0.2.0.1",
            "0..1",
            "0.2.x",
            "0.2.0-",
            "0.2.0/../x",
            "0.2.0?a=b",
        ] {
            assert!(release_version(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn finds_executables_on_path() {
        let fake = Fake::new(Some(0));
        let path = std::env::join_paths([fake.dir.join("bin"), fake.dir.clone()]).unwrap();
        assert_eq!(find_on_path("gh", Some(&path)), Some(fake.dir.join("gh")));
        // bin/multipass is not executable.
        assert_eq!(find_on_path("multipass", Some(&path)), None);
        assert_eq!(
            find_on_path("gh", Some(std::ffi::OsStr::new("relative"))),
            None
        );
    }
}

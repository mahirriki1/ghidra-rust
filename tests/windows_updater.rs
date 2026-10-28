//! Native Windows lifecycle tests. The fixture calls the production helper and
//! cleanup entry points without opening a renderer or a blocking error dialog.
#![cfg(windows)]
use ghidra_rust::model::FileIdentity;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait(process: &mut Process) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(75);
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "updater process timed out");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn eventually(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "updater cleanup/relaunch did not finish"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn identity(path: &Path) -> FileIdentity {
    FileIdentity::from_file(&File::open(path).unwrap()).unwrap()
}
fn guard(path: &Path) -> Value {
    json!({"path": path, "identity": identity(path)})
}
fn record(path: &Path) -> Value {
    let mut file = File::open(path).unwrap();
    let mut digest = Sha256::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut chunk).unwrap();
        if count == 0 {
            break;
        }
        digest.update(&chunk[..count]);
    }
    json!({"name": path.file_name().unwrap().to_str().unwrap(), "size": file.metadata().unwrap().len(), "sha256": format!("{:x}", digest.finalize())})
}

struct Fixture {
    stage: PathBuf,
    app: PathBuf,
    binary: PathBuf,
    result: PathBuf,
    parent: Process,
    helper: Process,
    original: FileIdentity,
    _root: tempfile::TempDir,
}
impl Fixture {
    fn new(invalid_binary: bool, protected: bool) -> Option<Self> {
        let Some(driver) = std::env::var_os("GHIDRA_RUST_TEST_UPDATER_DRIVER") else {
            eprintln!(
                "Set GHIDRA_RUST_TEST_UPDATER_DRIVER to the built updater-test-driver.exe to run native lifecycle tests"
            );
            return None;
        };
        let root = tempfile::tempdir().unwrap();
        let install = root.path().join("installation");
        fs::create_dir(&install).unwrap();
        let app = install.join("app.exe");
        fs::copy(&driver, &app).unwrap();
        let app = fs::canonicalize(app).unwrap();
        let original = identity(&app);
        let stage = tempfile::Builder::new()
            .prefix("ghidra-update-")
            .tempdir_in(root.path())
            .unwrap()
            .keep();
        let stage = fs::canonicalize(stage).unwrap();
        fs::copy(&driver, stage.join("helper.exe")).unwrap();
        let binary = stage.join("ghidra-rust-0.0.9-windows-x64.exe");
        if invalid_binary {
            fs::write(&binary, b"verified but not an executable").unwrap();
        } else {
            fs::copy(&driver, &binary).unwrap();
        }
        let notices = stage.join("ghidra-rust-0.0.9-update-notices.txt");
        fs::write(&notices, b"Test notices accepted by the fixture").unwrap();
        let result = root.path().join("relaunch.json");
        let input = root.path().join("protected-input");
        fs::write(&input, b"protected input").unwrap();
        let parent = Process(
            Command::new(&app)
                .arg("--parent")
                .stdin(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut helper = Process(
            Command::new(stage.join("helper.exe"))
                .arg("--update-helper")
                .env("GHIDRA_RUST_TEST_UPDATER_RESULT", &result)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let plan = json!({"parent":parent.0.id(),"version":"0.0.9","executable":guard(&app),
            "protections":if protected {vec![guard(&input)]} else {vec![]}, "binary":record(&binary),"notices":record(&notices)});
        writeln!(helper.0.stdin.as_mut().unwrap(), "{plan}").unwrap();
        helper.0.stdin.as_mut().unwrap().flush().unwrap();
        let stdout = helper.0.stdout.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            let _ = sender.send(line);
        });
        let line = receiver
            .recv_timeout(Duration::from_secs(45))
            .expect("helper readiness timed out");
        assert_eq!(serde_json::from_str::<String>(&line).unwrap(), "ready");
        Some(Self {
            _root: root,
            stage,
            app,
            binary,
            result,
            parent,
            helper,
            original,
        })
    }
    fn commit(&mut self) {
        let project = self._root.path().join("saved-project.grproj");
        writeln!(
            self.helper.0.stdin.as_mut().unwrap(),
            "{}",
            serde_json::to_string(&Some(project)).unwrap()
        )
        .unwrap();
        self.helper.0.stdin.take();
    }
    fn exit_parent(&mut self) {
        self.parent.0.stdin.take();
        assert!(wait(&mut self.parent).success());
    }
    fn assert_no_installation_clutter(&self) {
        assert_eq!(fs::read_dir(self.app.parent().unwrap()).unwrap().count(), 1);
    }
}

#[test]
fn replaces_running_app_at_same_path_relaunches_project_and_removes_helper() {
    let Some(mut fixture) = Fixture::new(false, false) else {
        return;
    };
    fixture.commit();
    // The old app is still mapped: publication must wait for its process exit.
    assert_eq!(identity(&fixture.app), fixture.original);
    fixture.exit_parent();
    assert!(wait(&mut fixture.helper).success());
    eventually(|| fixture.result.exists() && !fixture.stage.exists());
    let project: Option<PathBuf> =
        serde_json::from_slice(&fs::read(&fixture.result).unwrap()).unwrap();
    assert_eq!(
        project,
        Some(fixture._root.path().join("saved-project.grproj"))
    );
    assert_ne!(identity(&fixture.app), fixture.original);
    fixture.assert_no_installation_clutter();
}

#[test]
fn locked_destination_preserves_installed_app_and_cleans_failed_helper() {
    let Some(mut fixture) = Fixture::new(false, false) else {
        return;
    };
    let lock = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&fixture.app)
        .unwrap();
    fixture.commit();
    fixture.exit_parent();
    assert!(!wait(&mut fixture.helper).success());
    drop(lock);
    eventually(|| !fixture.stage.exists());
    assert_eq!(identity(&fixture.app), fixture.original);
    assert!(!fixture.result.exists());
    fixture.assert_no_installation_clutter();
}

#[test]
fn failed_relaunch_cleans_failed_helper_without_deleting_installed_file() {
    let Some(mut fixture) = Fixture::new(true, false) else {
        return;
    };
    fixture.commit();
    fixture.exit_parent();
    assert!(!wait(&mut fixture.helper).success());
    eventually(|| !fixture.stage.exists());
    assert!(
        fs::read(&fixture.app).unwrap() == b"verified but not an executable",
        "the verified test payload must remain installed when relaunch fails"
    );
    fixture.assert_no_installation_clutter();
}

#[test]
fn cancellation_before_commit_preserves_running_app_and_cleans_helper() {
    let Some(mut fixture) = Fixture::new(false, false) else {
        return;
    };
    fixture.helper.0.stdin.take();
    assert!(!wait(&mut fixture.helper).success());
    eventually(|| !fixture.stage.exists());
    assert_eq!(identity(&fixture.app), fixture.original);
    fixture.exit_parent();
}

#[test]
fn failure_cleanup_keeps_substituted_protected_input_alias() {
    let Some(mut fixture) = Fixture::new(false, true) else {
        return;
    };
    // Replacing a pinned artifact changes its identity and signed bytes.
    let retired = fixture.stage.join("retired-binary");
    fs::rename(&fixture.binary, &retired).unwrap();
    fs::hard_link(
        fixture._root.path().join("protected-input"),
        &fixture.binary,
    )
    .unwrap();
    fixture.commit();
    fixture.exit_parent();
    assert!(!wait(&mut fixture.helper).success());
    eventually(|| !fixture.stage.join("helper.exe").exists());
    assert_eq!(fs::read(&fixture.binary).unwrap(), b"protected input");
    assert_eq!(
        fs::read(fixture._root.path().join("protected-input")).unwrap(),
        b"protected input"
    );
    assert!(retired.exists());
    assert_eq!(identity(&fixture.app), fixture.original);
}

#[test]
fn parent_exit_timeout_preserves_running_app_and_cleans_helper() {
    let Some(mut fixture) = Fixture::new(false, false) else {
        return;
    };
    fixture.commit();
    assert!(!wait(&mut fixture.helper).success());
    eventually(|| !fixture.stage.exists());
    assert_eq!(identity(&fixture.app), fixture.original);
    assert!(fixture.parent.0.try_wait().unwrap().is_none());
    fixture.exit_parent();
}

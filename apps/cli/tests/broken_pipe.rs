//! A reader that closed its end (`kekkai status | head`) ends the command quietly, as SIGPIPE
//! did for the Go CLI, with exit code 1.

use std::process::Command;

#[test]
fn a_closed_stdout_fails_quietly() {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let run = Command::new(env!("CARGO_BIN_EXE_kekkai"))
        .arg("--version")
        .stdout(writer)
        .output()
        .unwrap();
    assert_eq!(run.status.code(), Some(1), "{run:?}");
    assert!(
        run.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
}

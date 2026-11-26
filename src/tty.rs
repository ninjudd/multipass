//! Reading a line from the terminal without echoing it.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::process::Command;

/// Prompts on the terminal itself, never on stdin, so stdin stays free for
/// piped secrets. Echo is turned off with the system's `stty`, which avoids
/// both a dependency and unsafe terminal calls.
pub fn read_hidden(prompt: &str) -> io::Result<String> {
    let mut tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;

    // Echo goes off before the prompt appears, because `stty` takes a
    // moment to start and anything typed in that moment would be shown.
    stty(&tty, "-echo")?;
    let mut line = String::new();
    let read = tty
        .write_all(prompt.as_bytes())
        .and_then(|()| tty.flush())
        .and_then(|()| BufReader::new(&tty).read_line(&mut line));
    let restored = stty(&tty, "echo");
    tty.write_all(b"\n")?;
    read?;
    restored?;

    if !line.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the terminal closed",
        ));
    }
    line.pop();
    if line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

fn stty(tty: &File, setting: &str) -> io::Result<()> {
    let status = Command::new("/bin/stty")
        .arg(setting)
        .stdin(tty.try_clone()?)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("stty {setting} failed")))
    }
}

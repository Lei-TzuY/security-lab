use std::env;
use std::fs::File;
use std::io;
use std::path::Path;
use std::process;

fn main() {
    let mut args = env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| fail(2));

    match mode.as_str() {
        "allowed" => println!("allowed operation succeeded"),
        "forbidden-getpid" => forbidden_getpid(),
        "expect-env" => {
            let key = args.next().unwrap_or_else(|| fail(2));
            let expected = args.next().unwrap_or_else(|| fail(2));
            if env::var(&key).ok().as_deref() != Some(expected.as_str()) {
                fail(3);
            }
            if key != "PATH" && env::var_os("PATH").is_some() {
                fail(4);
            }
        }
        "expect-cwd" => {
            let expected = args.next().unwrap_or_else(|| fail(2));
            if env::current_dir().ok().as_deref() != Some(Path::new(&expected)) {
                fail(5);
            }
        }
        "exit" => {
            let code = args
                .next()
                .and_then(|value| value.parse::<i32>().ok())
                .unwrap_or_else(|| fail(2));
            process::exit(code);
        }
        "signal-term" => signal_term(),
        "nofile" => nofile(),
        "no-new-privs" => no_new_privs(),
        "write-marker" => {
            let path = args.next().unwrap_or_else(|| fail(2));
            if File::create(path).is_err() {
                fail(6);
            }
        }
        _ => fail(2),
    }
}

fn fail(code: i32) -> ! {
    process::exit(code)
}

#[cfg(target_os = "linux")]
fn forbidden_getpid() {
    unsafe {
        *libc::__errno_location() = 0;
        let result = libc::syscall(libc::SYS_getpid);
        let errno = *libc::__errno_location();
        if result == -1 && errno == libc::EPERM {
            process::exit(77);
        }
    }
    process::exit(7);
}

#[cfg(not(target_os = "linux"))]
fn forbidden_getpid() {
    process::exit(2);
}

#[cfg(target_os = "linux")]
fn signal_term() {
    unsafe {
        let pid = libc::syscall(libc::SYS_getpid);
        let tid = libc::syscall(libc::SYS_gettid);
        if pid < 0 || tid < 0 {
            fail(8);
        }
        let result = libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGTERM);
        if result != 0 {
            fail(9);
        }
    }
    fail(10);
}

#[cfg(not(target_os = "linux"))]
fn signal_term() {
    process::exit(2);
}

fn nofile() {
    let mut files = Vec::new();
    loop {
        match File::open("/dev/null") {
            Ok(file) => {
                files.push(file);
                if files.len() > 128 {
                    fail(11);
                }
            }
            Err(err) if err.raw_os_error() == Some(libc::EMFILE) => return,
            Err(err) => {
                eprintln!("unexpected open error: {err}");
                fail(12);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn no_new_privs() {
    let result = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if result != 1 {
        let err = io::Error::last_os_error();
        eprintln!("PR_GET_NO_NEW_PRIVS returned {result}: {err}");
        fail(13);
    }
}

#[cfg(not(target_os = "linux"))]
fn no_new_privs() {
    process::exit(2);
}

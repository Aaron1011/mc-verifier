use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let mut out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    out_path.push("dbclient");

    std::env::set_current_dir("dropbear").unwrap();

    /*run_command("make", &["clean"]);
    run_command("autoconf", &[]);
    run_command("autoheader", &[]);
    run_command("./configure", &[]);
    run_command("make", &[]);*/

    std::fs::copy("dbclient", out_path).unwrap();
}

fn run_command(cmd: &str, args: &[&str]) {
   if !Command::new(cmd)
        .args(args)
        .spawn()
        .expect("Failed to spawn command!")
        .wait()
        .expect("Faield to run command")
        .success() {
            panic!("{} failed!", cmd);
        }
}

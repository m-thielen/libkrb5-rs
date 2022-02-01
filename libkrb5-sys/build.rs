/*!
 * Build script for libkrb5-sys.
 *
 * Original https://github.com/ironthree/libkrb5-rs/blob/master/libkrb5-sys/build.rs
 *
 * Modified to add PKG_CONFIG_PATH to the environment so the Homebrew Heimdal libkrb5 is found.
 */

use std::env;
use std::ops::Deref;
use std::path::PathBuf;
use std::process;
use std::process::Command;

use pkg_config::probe_library;

fn main() {
    let mut library_ret = probe_library("krb5");
    if library_ret.is_err() {
        /* pkg-config failed to find krb5 library.
         * Check if there's Homebrew installed; if so, we use it to locate heimdal kerberos lib.
         * Calling `brew --prefix heimdal` should yield the heimdal's installation path to stdout.  
         */
        let brew_out = Command::new("brew")
            .arg("--prefix")
            .arg("heimdal")
            .output()
            .expect("krb5 library not found and failed to execute `brew --prefix` to locate it");
        if !brew_out.status.success() {
            eprintln!(
                "Failed to run brew to locate heimdal krb5: code {}",
                brew_out.status.code().unwrap()
            );
            process::exit(1);
        }
        if brew_out.stdout[0] != b'/' {
            /* we expect an absolute path, so we treat this as an error */
            eprintln!("Failed to locate krb5: {}", String::from_utf8_lossy(&brew_out.stdout));
            process::exit(2);
        }

        /* the krb5.pc file should be in <heimdal path>/lib/pkgconfig */
        let mut heimdal_pc_path = PathBuf::from(String::from_utf8_lossy(&brew_out.stdout).deref().trim_end());
        heimdal_pc_path.push("lib/pkgconfig");

        /* prepend to or create PKG_CONFIG_PATH env var */
        let pkg_path = if let Ok(val) = env::var("PKG_CONFIG_PATH") {
            /* append to existing PKG_CONFIG_PATH */
            format!("{}:{}", heimdal_pc_path.to_str().unwrap(), val)
        } else {
            /* create new PKG_CONFIG_PATH env var */
            String::from(heimdal_pc_path.to_str().unwrap())
        };

        env::set_var("PKG_CONFIG_PATH", pkg_path.clone());
        eprintln!("Setting PKG_CONFIG_PATH to {}", pkg_path);

        /* try probe again */
        library_ret = probe_library("krb5");
    }

    let library = library_ret.expect("Failed to probe krb5");
    for lib in library.libs {
        println!("cargo:rustc-link-lib={}", lib);
    }

    let bindings = bindgen::Builder::default()
        .rust_target(bindgen::RustTarget::Stable_1_40)
        .header("src/wrapper.h")
        .whitelist_type("(_|)krb5.*")
        .whitelist_function("krb5.*")
        .whitelist_var("ADDRTYPE_.*")
        .whitelist_var("AD_TYPE_.*")
        .whitelist_var("AP_OPTS_.*")
        .whitelist_var("CKSUMTYPE_.*")
        .whitelist_var("ENCTYPE_.*")
        .whitelist_var("KDC_OPT_.*")
        .whitelist_var("KRB5.*")
        .whitelist_var("LR_TYPE_.*")
        .whitelist_var("MAX_KEYTAB_NAME_LEN")
        .whitelist_var("MSEC_.*")
        .whitelist_var("TKT_FLG_.*")
        .generate()
        .expect("Unable to generate bindings.");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Unable to write bindings to file.");
}

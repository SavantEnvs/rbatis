// Compiles ../lsan_off.cc (SPEC.md §6.2 item 15's build-time LeakSanitizer opt-out) via the `cc`
// crate and links it into the `decode` fuzz binary — the same mechanism libfuzzer-sys itself uses
// to compile its bundled C++ runtime.
fn main() {
    println!("cargo:rerun-if-changed=../lsan_off.cc");
    cc::Build::new()
        .cpp(true)
        .file("../lsan_off.cc")
        .compile("lsan_off");
}

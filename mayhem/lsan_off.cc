// Disables LeakSanitizer at build time (SPEC.md §6.2 item 15): `-fsanitize=address` always
// bundles LeakSanitizer in with no separate flag to exclude it, and leaks aren't the memory-safety
// class this fleet fuzzes for (ASan's heap-buffer-overflow/use-after-free/etc. and UBSan are).
// Compiled and linked into the `decode` fuzz binary via mayhem/fuzz/build.rs (the `cc` crate, the
// same way libfuzzer-sys compiles its own C++ runtime) — see mayhem/build.sh.
extern "C" int __lsan_is_turned_off() { return 1; }

fn main() {
    let is_msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");

    if  is_msvc{
        println!("cargo:rustc-link-arg=/NODEFAULTLIB");
        println!("cargo:rustc-link-arg=/ENTRY:start");
        println!("cargo:rustc-link-arg=/SUBSYSTEM:CONSOLE");
    }
}
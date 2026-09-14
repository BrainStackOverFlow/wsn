use wdll::{InMemoryDll, Peb};

#[test]
fn test_aa_test() {
    let peb = Peb::get();
    let ldr = peb.ldr();

    for entry in ldr.iter_entries() {
        let name = entry.name();
        // let aa = String::from_utf16_lossy(&name);
        let dll = entry.dll();
        println!("entry {name}")
    }

    let ntdll = InMemoryDll::get_loaded_ntdll().unwrap();

    println!("AA");
}
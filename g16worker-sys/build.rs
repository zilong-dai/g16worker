use std::path::Path;

fn main() -> anyhow::Result<()> {
    gobuild::Build::new()
        .file(concat!(env!("CARGO_MANIFEST_DIR"), "/../bin/main.go"))
        .out_dir(env!("CARGO_MANIFEST_DIR"))
        .buildmode(gobuild::BuildMode::CArchive)
        .compile("g16worker");

    bindgen::Builder::default()
        .header(concat!(env!("CARGO_MANIFEST_DIR"), "/libg16worker.h"))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(Path::new(&std::env::var("OUT_DIR")?).join("bindings.rs"))
        .expect("Couldn't write bindings!");

    Ok(())
}

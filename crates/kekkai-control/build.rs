fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    tonic_build::configure()
        .build_server(true)
        // The client and the descriptor set serve the Rust CLI (ADR 0033).
        .build_client(true)
        .file_descriptor_set_path(out.join("control.bin"))
        .compile_protos(
            &["../../proto/kekkai/control/v1/control.proto"],
            &["../../proto"],
        )?;
    Ok(())
}

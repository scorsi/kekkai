//! Generated types for the `kekkai.control.v1` package (0015). Source of truth: `proto/`.

pub mod v1 {
    tonic::include_proto!("kekkai.control.v1");
}

/// The encoded `FileDescriptorSet` of the protos, from which the CLI prints a reply in
/// protojson form (ADR 0033).
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/control.bin"));

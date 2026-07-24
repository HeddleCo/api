// SPDX-License-Identifier: Apache-2.0
use std::{env, fs, path::PathBuf};

#[path = "build_support/method_generation.rs"]
mod method_generation;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    unsafe { env::set_var("PROTOC", protoc) };

    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = root.join("proto");
    let package_root = proto_root.join("heddle/api/v1alpha1");
    let mut protos = fs::read_dir(&package_root)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "proto")
        })
        .collect::<Vec<_>>();
    protos.sort();

    let output = PathBuf::from(env::var("OUT_DIR")?);
    let descriptor = output.join("heddle_api_descriptor.bin");
    println!("cargo:rerun-if-changed={}", package_root.display());

    let mut config = prost_build::Config::new();
    config
        .boxed(".heddle.api.v1alpha1.PushClientFrame.frame.request")
        .file_descriptor_set_path(&descriptor)
        .compile_protos(&protos, &[proto_root])?;
    method_generation::write(&descriptor, &output.join("heddle_api_methods.rs"))?;
    Ok(())
}

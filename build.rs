// SPDX-License-Identifier: Apache-2.0
use std::{env, fs, path::PathBuf};

#[path = "build_support/attachment_generation.rs"]
mod attachment_generation;
#[path = "build_support/method_generation.rs"]
mod method_generation;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    unsafe { env::set_var("PROTOC", protoc) };

    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = root.join("proto");
    let mut protos = Vec::new();
    for package in ["v1alpha1", "v2alpha1"] {
        let package_root = proto_root.join("heddle/api").join(package);
        println!("cargo:rerun-if-changed={}", package_root.display());
        for entry in fs::read_dir(package_root)? {
            let path = entry?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "proto")
            {
                protos.push(path);
            }
        }
    }
    protos.sort();

    let output = PathBuf::from(env::var("OUT_DIR")?);
    let descriptor = output.join("heddle_api_descriptor.bin");

    let mut config = prost_build::Config::new();
    // These generated oneofs are bounded, single-message values. Keep them
    // inline rather than imposing an allocation on each streamed record.
    // Revisit their layout with measurements in the consuming transport.
    for oneof in [
        "ResolveDiscussionRequest.resolution",
        "ThreadListEvent.payload",
        "AttentionEvent.payload",
        "NotificationEvent.payload",
        "OperationEvent.payload",
        "OwnershipEvent.payload",
        "ReplicateThreadRequest.body",
        "FetchClientFrame.body",
        "FetchServerFrame.body",
    ] {
        config.type_attribute(
            format!(".heddle.api.v2alpha1.{oneof}"),
            "#[allow(clippy::large_enum_variant)]",
        );
    }
    config
        .boxed(".heddle.api.v1alpha1.PushClientFrame.frame.request")
        .boxed(".heddle.api.v1alpha1.BootstrapOwnerRootRequest.approval.deferred_human")
        .boxed(".heddle.api.v1alpha1.PullServerFrame.frame.state_attachment")
        .boxed(".heddle.api.v1alpha1.ListDiscussionsResponse.frame.item")
        .file_descriptor_set_path(&descriptor)
        .compile_protos(&protos, &[proto_root])?;
    method_generation::write(
        &descriptor,
        &output.join("heddle_api_methods.rs"),
        "heddle.api.v1alpha1",
    )?;
    method_generation::write(
        &descriptor,
        &output.join("heddle_api_v2_methods.rs"),
        "heddle.api.v2alpha1",
    )?;
    attachment_generation::write(
        &descriptor,
        &output.join("heddle_api_attachment_authorization.rs"),
    )?;
    Ok(())
}

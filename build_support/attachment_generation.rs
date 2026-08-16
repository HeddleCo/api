// SPDX-License-Identifier: Apache-2.0
use std::{error::Error, fs, path::Path};

use prost_reflect::{DescriptorPool, Kind, Value};

const KIND_ENUM: &str = "heddle.api.v1alpha1.StateAttachmentKind";
const CLASS_ENUM: &str = "heddle.api.v1alpha1.StateAttachmentAuthorizationClassification";
const CLASS_OPTION: &str = "heddle.api.v1alpha1.state_attachment_authorization_classification";

pub fn write(descriptor_path: &Path, output_path: &Path) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(descriptor_path)?;
    let pool = DescriptorPool::decode(bytes.as_slice())?;
    let kinds = pool
        .get_enum_by_name(KIND_ENUM)
        .ok_or_else(|| format!("descriptor is missing {KIND_ENUM}"))?;
    let classes = pool
        .get_enum_by_name(CLASS_ENUM)
        .ok_or_else(|| format!("descriptor is missing {CLASS_ENUM}"))?;
    let option = pool
        .get_extension_by_name(CLASS_OPTION)
        .ok_or_else(|| format!("descriptor is missing {CLASS_OPTION}"))?;
    let Kind::Enum(option_enum) = option.kind() else {
        return Err(format!("{CLASS_OPTION} is not an enum option").into());
    };
    if option_enum.full_name() != classes.full_name() {
        return Err(format!("{CLASS_OPTION} has the wrong enum type").into());
    }

    let mut rows = Vec::new();
    for kind in kinds.values().filter(|value| value.number() != 0) {
        let options = kind.options();
        let value = options.get_extension(&option);
        let Value::EnumNumber(class_number) = value.as_ref() else {
            return Err(format!(
                "{} has a non-enum authorization classification",
                kind.name()
            )
            .into());
        };
        if *class_number == 0 {
            return Err(format!(
                "{} is missing a non-UNSPECIFIED state_attachment_authorization_classification",
                kind.name()
            )
            .into());
        }
        let class = classes.get_value(*class_number).ok_or_else(|| {
            format!(
                "{} has unknown attachment authorization classification {}",
                kind.name(),
                class_number
            )
        })?;
        rows.push((
            rust_variant(kind.name(), "STATE_ATTACHMENT_KIND_")?,
            rust_variant(
                class.name(),
                "STATE_ATTACHMENT_AUTHORIZATION_CLASSIFICATION_",
            )?,
        ));
    }

    let mut output = String::from(
        "/// Generated exhaustive authorization classification for every current state attachment kind.\n\
         pub const STATE_ATTACHMENT_AUTHORIZATION_CONFORMANCE: &[(\n\
             heddle::api::v1alpha1::StateAttachmentKind,\n\
             heddle::api::v1alpha1::StateAttachmentAuthorizationClassification,\n\
         )] = &[\n",
    );
    for (kind, class) in rows {
        output.push_str(&format!(
            "    (heddle::api::v1alpha1::StateAttachmentKind::{kind}, heddle::api::v1alpha1::StateAttachmentAuthorizationClassification::{class}),\n"
        ));
    }
    output.push_str(
        "];\n\n\
         /// Returns the generated fail-closed classification for a known attachment kind.\n\
         pub fn state_attachment_authorization_classification(\n\
             kind: heddle::api::v1alpha1::StateAttachmentKind,\n\
         ) -> Option<heddle::api::v1alpha1::StateAttachmentAuthorizationClassification> {\n\
             STATE_ATTACHMENT_AUTHORIZATION_CONFORMANCE\n\
                 .iter()\n\
                 .find_map(|(candidate, classification)| (*candidate == kind).then_some(*classification))\n\
         }\n",
    );
    fs::write(output_path, output)?;
    Ok(())
}

fn rust_variant(name: &str, prefix: &str) -> Result<String, Box<dyn Error>> {
    let name = name
        .strip_prefix(prefix)
        .ok_or_else(|| format!("enum value {name} does not start with {prefix}"))?;
    Ok(name
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => {
                    first.to_ascii_uppercase().to_string() + &chars.as_str().to_ascii_lowercase()
                }
                None => String::new(),
            }
        })
        .collect())
}

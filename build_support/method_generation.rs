// SPDX-License-Identifier: Apache-2.0
use std::{error::Error, fs, path::Path};

use prost_reflect::{
    DescriptorPool, DynamicMessage, ExtensionDescriptor, Kind, ReflectMessage, Value,
};

const PACKAGE: &str = "heddle.api.v1alpha1";

struct Method {
    path: String,
    input: String,
    output: String,
    route: String,
    streaming: &'static str,
    effect: String,
    retry: String,
    signing: String,
    authorization_access: String,
    client_operation_id_required: bool,
    maturity: String,
    deployments: Vec<String>,
}

pub fn write(descriptor_path: &Path, output_path: &Path) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(descriptor_path)?;
    let pool = DescriptorPool::decode(bytes.as_slice())?;
    let service_contract = extension(&pool, "service_contract")?;
    let rpc_contract = extension(&pool, "rpc_contract")?;
    let mut methods = Vec::new();

    for service in pool
        .services()
        .filter(|service| service.package_name() == PACKAGE)
    {
        let service_options = extension_message(service.options(), &service_contract)?;
        let maturity = enum_variant(&service_options, "maturity", "SERVICE_MATURITY_")?;
        let deployments =
            enum_variants(&service_options, "deployment_targets", "DEPLOYMENT_TARGET_")?;
        for method in service.methods() {
            let options = extension_message(method.options(), &rpc_contract)?;
            let streaming = match (
                method.method_descriptor_proto().client_streaming(),
                method.method_descriptor_proto().server_streaming(),
            ) {
                (false, false) => "Unary",
                (true, false) => "ClientStreaming",
                (false, true) => "ServerStreaming",
                (true, true) => "Bidirectional",
            };
            methods.push(Method {
                path: format!("/{}/{}", service.full_name(), method.name()),
                input: method.input().full_name().to_string(),
                output: method.output().full_name().to_string(),
                route: format!("{}{}", service.name(), method.name()),
                streaming,
                effect: enum_variant(&options, "effect", "RPC_EFFECT_")?,
                retry: enum_variant(&options, "retry_behavior", "RETRY_BEHAVIOR_")?,
                signing: enum_variant(&options, "signing_tier", "SIGNING_TIER_")?,
                authorization_access: enum_variant(
                    &options,
                    "authorization_access",
                    "AUTHORIZATION_ACCESS_",
                )?,
                client_operation_id_required: bool_value(&options, "client_operation_id_required")?,
                maturity: maturity.clone(),
                deployments: deployments.clone(),
            });
        }
    }
    methods.sort_by(|left, right| left.path.cmp(&right.path));
    fs::write(output_path, render(&methods))?;
    Ok(())
}

fn bool_value(message: &DynamicMessage, field_name: &str) -> Result<bool, Box<dyn Error>> {
    let value = message
        .get_field_by_name(field_name)
        .ok_or_else(|| format!("option message is missing {field_name}"))?;
    match value.as_ref() {
        Value::Bool(value) => Ok(*value),
        _ => Err(format!("option field {field_name} is not a bool").into()),
    }
}

fn extension(pool: &DescriptorPool, name: &str) -> Result<ExtensionDescriptor, Box<dyn Error>> {
    pool.get_extension_by_name(&format!("{PACKAGE}.{name}"))
        .ok_or_else(|| format!("descriptor is missing {PACKAGE}.{name}").into())
}

fn extension_message(
    options: DynamicMessage,
    extension: &ExtensionDescriptor,
) -> Result<DynamicMessage, Box<dyn Error>> {
    match options.get_extension(extension).as_ref() {
        Value::Message(message) => Ok(message.clone()),
        _ => Err(format!("{} is not a message option", extension.full_name()).into()),
    }
}

fn enum_variant(
    message: &DynamicMessage,
    field_name: &str,
    prefix: &str,
) -> Result<String, Box<dyn Error>> {
    let field = message
        .descriptor()
        .get_field_by_name(field_name)
        .ok_or_else(|| format!("option message is missing {field_name}"))?;
    let Kind::Enum(descriptor) = field.kind() else {
        return Err(format!("option field {field_name} is not an enum").into());
    };
    let value = message.get_field(&field);
    let Value::EnumNumber(number) = value.as_ref() else {
        return Err(format!("option field {field_name} has the wrong value type").into());
    };
    let enum_value = descriptor
        .get_value(*number)
        .ok_or_else(|| format!("option field {field_name} has unknown value {number}"))?;
    rust_variant(enum_value.name(), prefix)
}

fn enum_variants(
    message: &DynamicMessage,
    field_name: &str,
    prefix: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let field = message
        .descriptor()
        .get_field_by_name(field_name)
        .ok_or_else(|| format!("option message is missing {field_name}"))?;
    let Kind::Enum(descriptor) = field.kind() else {
        return Err(format!("option field {field_name} is not an enum").into());
    };
    let value = message.get_field(&field);
    let Value::List(values) = value.as_ref() else {
        return Err(format!("option field {field_name} is not repeated").into());
    };
    values
        .iter()
        .map(|value| {
            let Value::EnumNumber(number) = value else {
                return Err(format!("option field {field_name} contains a non-enum").into());
            };
            let enum_value = descriptor
                .get_value(*number)
                .ok_or_else(|| format!("option field {field_name} has unknown value {number}"))?;
            rust_variant(enum_value.name(), prefix)
        })
        .collect()
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

fn render(methods: &[Method]) -> String {
    let mut output = String::from(
        "/// Generated stable route identity for every declared contract method.\n\
         #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]\n\
         pub enum MethodRoute {\n",
    );
    for method in methods {
        output.push_str(&format!("    {},\n", method.route));
    }
    output.push_str(
        "}\n\n\
         /// Generated transport-neutral method contract.\n\
         #[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
         pub struct MethodDescriptor {\n\
         pub path: &'static str,\n\
         pub input: &'static str,\n\
         pub output: &'static str,\n\
         pub streaming: StreamingShape,\n\
         pub effect: RpcEffect,\n\
         pub retry_behavior: RetryBehavior,\n\
         pub signing_tier: SigningTier,\n\
         pub authorization_access: AuthorizationAccess,\n\
         pub client_operation_id_required: bool,\n\
         pub maturity: ServiceMaturity,\n\
         pub deployment_targets: &'static [DeploymentTarget],\n\
         pub route: MethodRoute,\n\
         }\n\n\
         /// All declared contract methods, sorted by fully-qualified path.\n\
         pub const ALL_METHODS: &[MethodDescriptor] = &[\n",
    );
    for method in methods {
        let deployments = method
            .deployments
            .iter()
            .map(|value| format!("DeploymentTarget::{value}"))
            .collect::<Vec<_>>()
            .join(", ");
        output.push_str(&format!(
            "MethodDescriptor {{ path: {:?}, input: {:?}, output: {:?}, streaming: StreamingShape::{}, effect: RpcEffect::{}, retry_behavior: RetryBehavior::{}, signing_tier: SigningTier::{}, authorization_access: AuthorizationAccess::{}, client_operation_id_required: {}, maturity: ServiceMaturity::{}, deployment_targets: &[{}], route: MethodRoute::{} }},\n",
            method.path,
            method.input,
            method.output,
            method.streaming,
            method.effect,
            method.retry,
            method.signing,
            method.authorization_access,
            method.client_operation_id_required,
            method.maturity,
            deployments,
            method.route,
        ));
    }
    output.push_str(
        "] ;\n\n\
         /// Looks up a declared method by its canonical fully-qualified path.\n\
         pub fn method_descriptor(path: &str) -> Option<&'static MethodDescriptor> {\n\
         ALL_METHODS.binary_search_by_key(&path, |method| method.path).ok().map(|index| &ALL_METHODS[index])\n\
         }\n",
    );
    output
}

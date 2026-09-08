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
    live_stream: bool,
    effect: String,
    retry: String,
    signing: String,
    signing_identity: String,
    authorization_access: String,
    authorization_role: String,
    authorization_scope: String,
    authorization_existence: String,
    authorization_targets: Vec<(String, String)>,
    client_operation_id_required: bool,
    client_operation_id_field_number: Option<u32>,
    maturity: String,
    deployments: Vec<String>,
}

pub fn write(
    descriptor_path: &Path,
    output_path: &Path,
    package: &str,
) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(descriptor_path)?;
    let pool = DescriptorPool::decode(bytes.as_slice())?;
    let service_contract = extension(&pool, "service_contract")?;
    let rpc_contract = extension(&pool, "rpc_contract")?;
    let mut methods = Vec::new();

    for service in pool
        .services()
        .filter(|service| service.package_name() == package)
    {
        let service_options = extension_message(service.options(), &service_contract)?;
        let maturity = enum_variant(&service_options, "maturity", "SERVICE_MATURITY_")?;
        let deployments =
            enum_variants(&service_options, "deployment_targets", "DEPLOYMENT_TARGET_")?;
        for method in service.methods() {
            let options = extension_message(method.options(), &rpc_contract)?;
            let method_maturity = enum_variant_override(&options, "maturity", "SERVICE_MATURITY_")?
                .unwrap_or_else(|| maturity.clone());
            let method_deployments =
                enum_variants(&options, "deployment_targets", "DEPLOYMENT_TARGET_")?;
            let method_deployments = if method_deployments.is_empty() {
                deployments.clone()
            } else {
                method_deployments
            };
            let streaming = match (
                method.method_descriptor_proto().client_streaming(),
                method.method_descriptor_proto().server_streaming(),
            ) {
                (false, false) => "Unary",
                (true, false) => "ClientStreaming",
                (false, true) => "ServerStreaming",
                (true, true) => "Bidirectional",
            };
            let live_stream = bool_value(&options, "live_stream")?;
            if live_stream && !method.method_descriptor_proto().server_streaming() {
                return Err(format!(
                    "{}.{} declares live lifetime without a response stream",
                    service.full_name(),
                    method.name()
                )
                .into());
            }
            let client_operation_id_field_number = method
                .input()
                .get_field_by_name("client_operation_id")
                .map(|field| field.number());
            methods.push(Method {
                path: format!("/{}/{}", service.full_name(), method.name()),
                input: method.input().full_name().to_string(),
                output: method.output().full_name().to_string(),
                route: format!("{}{}", service.name(), method.name()),
                streaming,
                live_stream,
                effect: enum_variant(&options, "effect", "RPC_EFFECT_")?,
                retry: enum_variant(&options, "retry_behavior", "RETRY_BEHAVIOR_")?,
                signing: enum_variant(&options, "signing_tier", "SIGNING_TIER_")?,
                signing_identity: enum_variant(
                    &options,
                    "signing_identity",
                    "STABLE_SIGNING_IDENTITY_",
                )?,
                authorization_access: enum_variant(
                    &options,
                    "authorization_access",
                    "AUTHORIZATION_ACCESS_",
                )?,
                authorization_role: enum_variant(
                    &options,
                    "authorization_role",
                    "AUTHORIZATION_ROLE_",
                )?,
                authorization_scope: enum_variant(
                    &options,
                    "authorization_scope_source",
                    "AUTHORIZATION_SCOPE_SOURCE_",
                )?,
                authorization_existence: enum_variant(
                    &options,
                    "authorization_existence",
                    "AUTHORIZATION_EXISTENCE_",
                )?,
                authorization_targets: authorization_targets(&options)?,
                client_operation_id_required: bool_value(&options, "client_operation_id_required")?,
                client_operation_id_field_number,
                maturity: method_maturity,
                deployments: method_deployments,
            });
        }
    }
    methods.sort_by(|left, right| left.path.cmp(&right.path));
    let mut generated = render(&methods, package == "heddle.api.v2alpha1");
    if package == "heddle.api.v2alpha1" {
        generated.push_str(
            "\n/// Typed operations derived from the protobuf method descriptors.\npub mod rpc {\n",
        );
        for (index, method) in methods.iter().enumerate() {
            let input = format!("crate::{}", method.input.replace('.', "::"));
            let output = format!("crate::{}", method.output.replace('.', "::"));
            let marker = match method.streaming {
                "Unary" => "UnaryRpc",
                "ServerStreaming" => "ServerStreamingRpc",
                "ClientStreaming" => "ClientStreamingRpc",
                _ => "BidirectionalRpc",
            };
            generated.push_str(&format!(
                "pub struct {route};\nimpl super::client::Rpc for {route} {{ type Request = {input}; type Response = {output}; const METHOD: &'static super::MethodDescriptor = &super::ALL_METHODS[{index}]; }}\nimpl super::client::{marker} for {route} {{}}\n",
                route = method.route,
            ));
        }
        generated.push_str("}\n");
    }
    fs::write(output_path, generated)?;
    Ok(())
}

fn authorization_targets(
    options: &DynamicMessage,
) -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let value = options
        .get_field_by_name("authorization_request_targets")
        .ok_or("missing authorization targets")?;
    let Value::List(targets) = value.as_ref() else {
        return Err("authorization targets must be a list".into());
    };
    targets
        .iter()
        .map(|value| {
            let Value::Message(target) = value else {
                return Err("authorization target must be a message".into());
            };
            let value = target
                .get_field_by_name("path")
                .ok_or("missing target path")?;
            let Value::String(path) = value.as_ref() else {
                return Err("target path must be a string".into());
            };
            Ok((
                path.clone(),
                enum_variant(target, "role", "AUTHORIZATION_ROLE_")?,
            ))
        })
        .collect()
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

fn enum_variant_override(
    message: &DynamicMessage,
    field_name: &str,
    prefix: &str,
) -> Result<Option<String>, Box<dyn Error>> {
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
    if *number == 0 {
        return Ok(None);
    }
    let enum_value = descriptor
        .get_value(*number)
        .ok_or_else(|| format!("option field {field_name} has unknown value {number}"))?;
    rust_variant(enum_value.name(), prefix).map(Some)
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

fn render(methods: &[Method], complete_policy: bool) -> String {
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
         pub live_stream: bool,\n\
         pub effect: RpcEffect,\n\
         pub retry_behavior: RetryBehavior,\n\
         pub signing_tier: SigningTier,\n\
         pub authorization_access: AuthorizationAccess,\n",
    );
    if complete_policy {
        output.push_str("pub signing_identity: crate::heddle::api::v1alpha1::StableSigningIdentity,\npub authorization: AuthorizationPolicy,\n");
    }
    output.push_str(
        "\
         pub client_operation_id_required: bool,\n\
         pub client_operation_id_field_number: Option<u32>,\n\
         pub maturity: ServiceMaturity,\n\
         pub deployment_targets: &'static [DeploymentTarget],\n\
         pub route: MethodRoute,\n\
         }\n\n\
         /// All declared contract methods, sorted by fully-qualified path.\n\
         pub const ALL_METHODS: &[MethodDescriptor] = &[\n",
    );
    for method in methods {
        let policy = if complete_policy {
            let targets = method.authorization_targets.iter().map(|(path, role)| format!(
                "AuthorizationTarget {{ path: {path:?}, role: crate::heddle::api::v1alpha1::AuthorizationRole::{role} }}"
            )).collect::<Vec<_>>().join(", ");
            format!(
                "signing_identity: crate::heddle::api::v1alpha1::StableSigningIdentity::{}, authorization: AuthorizationPolicy {{ role: crate::heddle::api::v1alpha1::AuthorizationRole::{}, scope_source: crate::heddle::api::v1alpha1::AuthorizationScopeSource::{}, existence: crate::heddle::api::v1alpha1::AuthorizationExistence::{}, targets: &[{}] }}, ",
                method.signing_identity,
                method.authorization_role,
                method.authorization_scope,
                method.authorization_existence,
                targets
            )
        } else {
            String::new()
        };
        let deployments = method
            .deployments
            .iter()
            .map(|value| format!("DeploymentTarget::{value}"))
            .collect::<Vec<_>>()
            .join(", ");
        output.push_str(&format!(
            "MethodDescriptor {{ {policy}path: {:?}, input: {:?}, output: {:?}, streaming: StreamingShape::{}, live_stream: {}, effect: RpcEffect::{}, retry_behavior: RetryBehavior::{}, signing_tier: SigningTier::{}, authorization_access: AuthorizationAccess::{}, client_operation_id_required: {}, client_operation_id_field_number: {:?}, maturity: ServiceMaturity::{}, deployment_targets: &[{}], route: MethodRoute::{} }},\n",
            method.path,
            method.input,
            method.output,
            method.streaming,
            method.live_stream,
            method.effect,
            method.retry,
            method.signing,
            method.authorization_access,
            method.client_operation_id_required,
            method.client_operation_id_field_number,
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

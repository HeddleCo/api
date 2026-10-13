//! Canonical signed mention/tag components for portable collaboration operations.
//! Hosts still verify the enclosing original operation, actor, causal frontier,
//! request correspondence and live authority. References never grant access.
use crate::heddle::api::v1alpha2 as api;
use crate::hybrid_codec::Reject;
use serde::Serialize;

pub const MAX_COLLABORATION_MENTIONS: usize = 128;
pub const MAX_MENTION_PATH_BYTES: usize = 4096;
pub const MAX_MENTION_SYMBOL_ID_BYTES: usize = 4096;

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Mention<'a> {
    Spool {
        spool: BinaryUuid,
    },
    Thread {
        spool: BinaryUuid,
        thread: &'a [u8],
    },
    State {
        spool: BinaryUuid,
        state: &'a [u8],
    },
    GitCommit {
        spool: BinaryUuid,
        oid: &'a str,
    },
    Checkout {
        spool: BinaryUuid,
        device: &'a [u8],
        id: &'a str,
    },
    Record {
        spool: Option<BinaryUuid>,
        record_kind: &'a str,
        id: &'a str,
    },
    Device {
        key: &'a [u8],
    },
    Principal {
        principal_id: BinaryUuid,
    },
    Source {
        target: SourceReference<'a>,
    },
}
struct BinaryUuid([u8; 16]);
impl Serialize for BinaryUuid {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}
fn uuid(id: &str) -> Result<BinaryUuid, Reject> {
    if id.len() != 36
        || [8, 13, 18, 23].iter().any(|&i| id.as_bytes()[i] != b'-')
        || id
            .bytes()
            .enumerate()
            .any(|(i, c)| ![8, 13, 18, 23].contains(&i) && !matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(Reject::Canonical);
    }
    let bytes = hex::decode(id.replace('-', "")).map_err(|_| Reject::Canonical)?;
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| Reject::Canonical)?;
    if bytes == [0; 16] {
        return Err(Reject::Canonical);
    }
    Ok(BinaryUuid(bytes))
}
fn spool(value: Option<&api::SpoolRef>) -> Result<BinaryUuid, Reject> {
    uuid(&value.ok_or(Reject::Canonical)?.id)
}
fn fixed(value: &[u8]) -> Result<&[u8], Reject> {
    if value.len() != 32 {
        return Err(Reject::Canonical);
    }
    Ok(value)
}
fn text(value: &str, max: usize, empty: bool) -> Result<(), Reject> {
    if value.len() > max {
        return Err(Reject::Bounds);
    }
    if (!empty && value.trim().is_empty()) || value.chars().any(char::is_control) {
        return Err(Reject::Canonical);
    }
    Ok(())
}
fn path(value: &str) -> Result<(), Reject> {
    text(value, MAX_MENTION_PATH_BYTES, false)?;
    if value.contains(['\\', ':']) || value.split('/').any(|s| matches!(s, "" | "." | "..")) {
        return Err(Reject::Canonical);
    }
    Ok(())
}
fn oid(value: &str) -> Result<&str, Reject> {
    if ![40, 64].contains(&value.len())
        || !value
            .bytes()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(Reject::Canonical);
    }
    Ok(value)
}
#[derive(Serialize)]
struct Scope<'a> {
    spool: BinaryUuid,
    thread: Option<&'a [u8]>,
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Revision<'a> {
    State { state_id: &'a [u8] },
    GitCommit { oid: &'a str },
}
#[derive(Serialize)]
struct Source<'a> {
    revision: Revision<'a>,
    path: &'a str,
    symbol_id: &'a str,
    start_line: Option<u32>,
    end_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<Target<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_kind: Option<&'a str>,
}
#[derive(Serialize)]
struct SourceReference<'a> {
    scope: Scope<'a>,
    source: Source<'a>,
}
fn source_parts<'a>(
    revision: Option<&'a api::RevisionRef>,
    source_path: &'a str,
    symbol_id: &'a str,
    start_line: Option<u32>,
    end_line: Option<u32>,
    owning_thread: Option<&'a api::ThreadRef>,
) -> Result<SourceReference<'a>, Reject> {
    path(source_path)?;
    text(symbol_id, MAX_MENTION_SYMBOL_ID_BYTES, true)?;
    match (start_line, end_line) {
        (None, None) => {}
        (Some(start), Some(end)) if start > 0 && end >= start => {}
        _ => return Err(Reject::Canonical),
    }
    let r = revision.ok_or(Reject::Canonical)?;
    let thread = owning_thread
        .map(|t| {
            if t.spool != r.spool {
                return Err(Reject::Scope);
            }
            fixed(&t.id.as_ref().ok_or(Reject::Canonical)?.value)
        })
        .transpose()?;
    let revision = match r.revision.as_ref().ok_or(Reject::Canonical)? {
        api::revision_ref::Revision::State(s) => Revision::State {
            state_id: fixed(&s.value)?,
        },
        api::revision_ref::Revision::GitCommitOid(s) => Revision::GitCommit { oid: oid(s)? },
    };
    Ok(SourceReference {
        scope: Scope {
            spool: spool(r.spool.as_ref())?,
            thread,
        },
        source: Source {
            revision,
            path: source_path,
            symbol_id,
            start_line,
            end_line,
            target: None,
            path_kind: None,
        },
    })
}
fn source(value: &api::SourceMention) -> Result<SourceReference<'_>, Reject> {
    source_parts(
        value.revision.as_ref(),
        &value.path,
        &value.symbol_id,
        value.start_line,
        value.end_line,
        value.thread.as_ref(),
    )
}
/// Validate pinned coordinates, exact revision, bounds and optional Thread scope.
pub fn validate_source_mention(value: &api::SourceMention) -> Result<(), Reject> {
    source(value).map(|_| ())
}
fn endpoint(value: &api::EndpointRef) -> Result<&[u8], Reject> {
    if value.kind != api::EndpointKind::Device as i32 {
        return Err(Reject::Canonical);
    }
    fixed(&value.public_key)
}
fn mention(value: &api::EntityRef) -> Result<Mention<'_>, Reject> {
    use api::entity_ref::Entity as E;
    let (record, kind) = match value.entity.as_ref().ok_or(Reject::Canonical)? {
        E::Principal(r) => {
            return Ok(Mention::Principal {
                principal_id: uuid(&r.id)?,
            });
        }
        E::Source(r) => return Ok(Mention::Source { target: source(r)? }),
        E::Spool(r) => {
            return Ok(Mention::Spool {
                spool: spool(Some(r))?,
            });
        }
        E::Thread(r) => {
            return Ok(Mention::Thread {
                spool: spool(r.spool.as_ref())?,
                thread: fixed(&r.id.as_ref().ok_or(Reject::Canonical)?.value)?,
            });
        }
        E::Device(r) => return Ok(Mention::Device { key: endpoint(r)? }),
        E::Checkout(r) => {
            text(&r.id, 1024, false)?;
            return Ok(Mention::Checkout {
                spool: spool(r.spool.as_ref())?,
                device: endpoint(r.device.as_ref().ok_or(Reject::Canonical)?)?,
                id: &r.id,
            });
        }
        E::Revision(r) => {
            return match r.revision.as_ref().ok_or(Reject::Canonical)? {
                api::revision_ref::Revision::State(s) => Ok(Mention::State {
                    spool: spool(r.spool.as_ref())?,
                    state: fixed(&s.value)?,
                }),
                api::revision_ref::Revision::GitCommitOid(s) => Ok(Mention::GitCommit {
                    spool: spool(r.spool.as_ref())?,
                    oid: oid(s)?,
                }),
            };
        }
        E::Discussion(r) => (r, "discussion"),
        E::Context(r) => (r, "context"),
        E::Operation(r) => (r, "operation"),
        E::Run(r) => (r, "run"),
        E::Policy(r) => (r, "policy"),
        E::Analysis(r) => (r, "analysis"),
        E::Invitation(r) => (r, "invitation"),
        E::Grant(r) => (r, "grant"),
        E::DiscussionTurn(r) => (r, "discussion_turn"),
        E::Review(r) => (r, "review"),
        E::Notification(r) => (r, "notification"),
        E::AttentionItem(r) => (r, "attention_item"),
        E::Member(r) => (r, "member"),
        E::ApprovalGroup(r) => (r, "approval_group"),
        E::Session(r) => (r, "session"),
        E::SignupInvitation(r) => (r, "signup_invitation"),
        E::TimelineEvent(r) => (r, "timeline_event"),
        E::Artifact(r) => (r, "artifact"),
        E::Mount(r) => (r, "mount"),
        E::SupportAccess(r) => (r, "support_access"),
        E::DeviceRecord(r) => (r, "device_record"),
        E::Delegation(r) => (r, "delegation"),
        E::Recovery(r) => (r, "recovery"),
        E::OwnerTransition(r) => (r, "owner_transition"),
        E::Billing(r) => (r, "billing"),
        E::Evidence(r) => (r, "evidence"),
        E::CheckAcknowledgement(r) => (r, "check_acknowledgement"),
        E::ProviderConnection(r) => (r, "provider_connection"),
        E::RemoteLink(r) => (r, "remote_link"),
        E::Bookmark(_) | E::Passkey(_) | E::Agent(_) => return Err(Reject::Semantic),
    };
    text(&record.id, 1024, false)?;
    Ok(Mention::Record {
        spool: record.spool.as_ref().map(|s| spool(Some(s))).transpose()?,
        record_kind: kind,
        id: &record.id,
    })
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>, Reject> {
    let bytes = rmp_serde::to_vec_named(value).map_err(|_| Reject::Canonical)?;
    if bytes.len() > 256 * 1024 {
        return Err(Reject::Bounds);
    }
    Ok(bytes)
}
/// Exact named MessagePack map used in SharedCommand.metadata.mentions.
pub fn canonical_mention(value: &api::EntityRef) -> Result<Vec<u8>, Reject> {
    encode(&mention(value)?)
}
pub fn validate_mentions(values: &[api::EntityRef]) -> Result<(), Reject> {
    if values.len() > MAX_COLLABORATION_MENTIONS {
        return Err(Reject::Bounds);
    }
    for value in values {
        mention(value)?;
    }
    Ok(())
}
/// Preserve caller ordering; mention arrays are not sets and are never sorted.
pub fn canonical_mentions(values: &[api::EntityRef]) -> Result<Vec<u8>, Reject> {
    validate_mentions(values)?;
    encode(&values.iter().map(mention).collect::<Result<Vec<_>, _>>()?)
}

#[derive(Serialize)]
struct Target<'a> {
    target: &'a [u8],
    binding: Binding<'a>,
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Binding<'a> {
    ViewedThread,
    NamedThread {
        scope: Scope<'a>,
    },
    PinnedRevision {
        scope: Scope<'a>,
        revision: Revision<'a>,
    },
}
fn target(value: &api::SourceTargetReference) -> Result<Target<'_>, Reject> {
    use api::source_target_reference::Binding as B;
    let binding = match value.binding.as_ref().ok_or(Reject::Canonical)? {
        B::ViewedThread(true) => Binding::ViewedThread,
        B::NamedThread(t) => Binding::NamedThread {
            scope: Scope {
                spool: spool(t.spool.as_ref())?,
                thread: Some(fixed(&t.id.as_ref().ok_or(Reject::Canonical)?.value)?),
            },
        },
        B::PinnedRevision(p) => {
            let r = p.revision.as_ref().ok_or(Reject::Canonical)?;
            let thread = p
                .thread
                .as_ref()
                .map(|t| {
                    if t.spool != r.spool {
                        return Err(Reject::Scope);
                    }
                    fixed(&t.id.as_ref().ok_or(Reject::Canonical)?.value)
                })
                .transpose()?;
            let revision = match r.revision.as_ref().ok_or(Reject::Canonical)? {
                api::revision_ref::Revision::State(s) => Revision::State {
                    state_id: fixed(&s.value)?,
                },
                api::revision_ref::Revision::GitCommitOid(s) => {
                    Revision::GitCommit { oid: oid(s)? }
                }
            };
            Binding::PinnedRevision {
                scope: Scope {
                    spool: spool(r.spool.as_ref())?,
                    thread,
                },
                revision,
            }
        }
        _ => return Err(Reject::Canonical),
    };
    Ok(Target {
        target: fixed(&value.target_id)?,
        binding,
    })
}
fn annotation_source(
    value: &api::AnnotationSourceReference,
) -> Result<SourceReference<'_>, Reject> {
    let a = value.source.as_ref().ok_or(Reject::Canonical)?;
    let mut reference = source_parts(
        a.revision.as_ref(),
        &a.path,
        &a.symbol_id,
        a.start_line,
        a.end_line,
        a.thread.as_ref(),
    )?;
    let path_kind = match (
        api::SourcePathKindSource::try_from(a.path_kind_source),
        api::SourcePathKind::try_from(a.path_kind),
    ) {
        (Ok(api::SourcePathKindSource::Unspecified), Ok(api::SourcePathKind::Unspecified)) => None,
        (Ok(api::SourcePathKindSource::Recorded), Ok(api::SourcePathKind::File)) => Some("file"),
        (Ok(api::SourcePathKindSource::Recorded), Ok(api::SourcePathKind::Directory))
            if a.symbol_id.is_empty() && a.start_line.is_none() =>
        {
            Some("directory")
        }
        _ => return Err(Reject::Canonical),
    };
    reference.source.target = a.target.as_ref().map(target).transpose()?;
    reference.source.path_kind = path_kind;
    Ok(reference)
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Tag<'a> {
    Text {
        text: &'a str,
    },
    Symbol {
        name: &'a str,
        target: Option<SourceReference<'a>>,
    },
    Source {
        target: SourceReference<'a>,
    },
    Entity {
        target: Mention<'a>,
    },
    Property {
        key: &'a str,
        value: Scalar<'a>,
    },
}
#[derive(Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum Scalar<'a> {
    Text(&'a str),
    Boolean(bool),
    Integer(i64),
    Decimal(Decimal),
}
#[derive(Serialize)]
struct Decimal {
    coefficient: i64,
    scale: u32,
}
fn tags(values: &[api::AnnotationTag]) -> Result<Vec<Tag<'_>>, Reject> {
    if values.len() > 128 {
        return Err(Reject::Bounds);
    }
    let mut keys = std::collections::BTreeSet::new();
    values
        .iter()
        .map(|value| {
            use api::annotation_tag::Tag as T;
            Ok(match value.tag.as_ref().ok_or(Reject::Canonical)? {
                T::Text(s) => {
                    text(s, 512, false)?;
                    Tag::Text { text: s }
                }
                T::Symbol(s) => {
                    text(&s.name, 512, false)?;
                    Tag::Symbol {
                        name: &s.name,
                        target: s.target.as_ref().map(annotation_source).transpose()?,
                    }
                }
                T::Source(s) => Tag::Source {
                    target: annotation_source(s)?,
                },
                T::Entity(e) => Tag::Entity {
                    target: mention(e)?,
                },
                T::Property(p) => {
                    if p.key.is_empty()
                        || p.key.len() > 128
                        || !p
                            .key
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"_./-".contains(&c))
                        || !keys.insert(&p.key)
                    {
                        return Err(Reject::Canonical);
                    }
                    let scalar = p
                        .value
                        .as_ref()
                        .and_then(|v| v.value.as_ref())
                        .ok_or(Reject::Canonical)?;
                    use api::annotation_value::Value as V;
                    let value = match scalar {
                        V::Text(s) => {
                            if s.len() > 512 {
                                return Err(Reject::Bounds);
                            }
                            Scalar::Text(s)
                        }
                        V::Boolean(b) => Scalar::Boolean(*b),
                        V::Integer(i) => Scalar::Integer(*i),
                        V::Decimal(d) => {
                            if d.scale > 9 || (d.scale > 0 && d.coefficient % 10 == 0) {
                                return Err(Reject::Canonical);
                            }
                            Scalar::Decimal(Decimal {
                                coefficient: d.coefficient,
                                scale: d.scale,
                            })
                        }
                    };
                    Tag::Property { key: &p.key, value }
                }
            })
        })
        .collect()
}
/// Reuse the existing context tag encoding without coercion or sorting.
pub fn canonical_annotation_tags(values: &[api::AnnotationTag]) -> Result<Vec<u8>, Reject> {
    encode(&tags(values)?)
}
/// New action in schema-version-2 discussion content. Its enclosing immutable
/// operation carries actor, timestamp and original observed causal parents.
pub fn canonical_discussion_tag_edit(values: &[api::AnnotationTag]) -> Result<Vec<u8>, Reject> {
    #[derive(Serialize)]
    struct Edit<'a> {
        kind: &'static str,
        tags: Vec<Tag<'a>>,
    }
    encode(&Edit {
        kind: "edit_tags",
        tags: tags(values)?,
    })
}

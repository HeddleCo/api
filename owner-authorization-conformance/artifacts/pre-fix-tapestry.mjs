// @bun
var __defProp = Object.defineProperty;
var __returnValue = (v) => v;
function __exportSetter(name, newValue) {
  this[name] = __returnValue.bind(null, newValue);
}
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, {
      get: all[name],
      enumerable: true,
      configurable: true,
      set: __exportSetter.bind(all, name)
    });
};

// src/lib/owner-authorization/capability.ts
var exports_capability = {};
__export(exports_capability, {
  verifyCapabilityChain: () => verifyCapabilityChain,
  verifyAuthorizationBundle: () => verifyAuthorizationBundle,
  validatePathSegments: () => validatePathSegments,
  requestMatchesSelector: () => requestMatchesSelector,
  grantCovers: () => grantCovers,
  createOwnerAuthorizationSubmission: () => createOwnerAuthorizationSubmission,
  createDirectCapability: () => createDirectCapability,
  createChildCapability: () => createChildCapability,
  createAuthorizationBundle: () => createAuthorizationBundle,
  VerifiedCapability: () => VerifiedCapability,
  VerifiedAuthorizationBundle: () => VerifiedAuthorizationBundle
});

// src/lib/owner-authorization/canonical.ts
var exports_canonical = {};
__export(exports_canonical, {
  utf8: () => utf8,
  transitionBody: () => transitionBody,
  sha256: () => sha256,
  registrationBody: () => registrationBody,
  ownerRootWithoutId: () => ownerRootWithoutId,
  ownerRootBody: () => ownerRootBody,
  keyId: () => keyId,
  includesBytes: () => includesBytes,
  digest: () => digest,
  deferredBootstrapBody: () => deferredBootstrapBody,
  concatBytes: () => concatBytes,
  compareBytes: () => compareBytes,
  capabilityWithoutId: () => capabilityWithoutId,
  capabilityBody: () => capabilityBody,
  anonymousBody: () => anonymousBody,
  OWNER_TRANSITION_DOMAIN: () => OWNER_TRANSITION_DOMAIN,
  OWNER_ROOT_DOMAIN: () => OWNER_ROOT_DOMAIN,
  OWNER_CAPABILITY_DOMAIN: () => OWNER_CAPABILITY_DOMAIN,
  KEY_ID_DOMAIN: () => KEY_ID_DOMAIN,
  DEFERRED_BOOTSTRAP_DOMAIN: () => DEFERRED_BOOTSTRAP_DOMAIN,
  CanonicalWriter: () => CanonicalWriter,
  BOOTSTRAP_CHALLENGE_DOMAIN: () => BOOTSTRAP_CHALLENGE_DOMAIN,
  ANONYMOUS_REGISTRATION_DOMAIN: () => ANONYMOUS_REGISTRATION_DOMAIN,
  ANONYMOUS_ID_DOMAIN: () => ANONYMOUS_ID_DOMAIN,
  ANONYMOUS_CREDENTIAL_DOMAIN: () => ANONYMOUS_CREDENTIAL_DOMAIN
});

// src/lib/owner-authorization/error.ts
class OwnerAuthorizationError extends Error {
  code;
  details;
  constructor(code, message, details) {
    super(message);
    this.code = code;
    this.details = details;
    this.name = "OwnerAuthorizationError";
  }
}
function fail(code, message, details) {
  throw new OwnerAuthorizationError(code, message, details);
}
function requireValue(value, field) {
  if (value === undefined)
    fail("INVALID", `missing required field ${field}`);
  return value;
}
function assertBytes(value, length, field) {
  if (value.byteLength !== length) {
    fail("INVALID", `${field} must be exactly ${length} bytes`);
  }
}

// src/lib/owner-authorization/wire.ts
var exports_wire = {};
__export(exports_wire, {
  webAuthnOwnerRootApprovalCodec: () => webAuthnOwnerRootApprovalCodec,
  submitOwnerAuthorizationResponseCodec: () => submitOwnerAuthorizationResponseCodec,
  submitOwnerAuthorizationRequestCodec: () => submitOwnerAuthorizationRequestCodec,
  spoolSelectorCodec: () => spoolSelectorCodec,
  spoolCapabilityGrantCodec: () => spoolCapabilityGrantCodec,
  signedOwnerRootCodec: () => signedOwnerRootCodec,
  signedOwnerKeyTransitionCodec: () => signedOwnerKeyTransitionCodec,
  signedOwnerCapabilityCodec: () => signedOwnerCapabilityCodec,
  registerAnonymousKeyResponseCodec: () => registerAnonymousKeyResponseCodec,
  registerAnonymousKeyRequestCodec: () => registerAnonymousKeyRequestCodec,
  recoveryPolicyCodec: () => recoveryPolicyCodec,
  recoveryGuardianCodec: () => recoveryGuardianCodec,
  ownerRootCodec: () => ownerRootCodec,
  ownerKeyTransitionCodec: () => ownerKeyTransitionCodec,
  ownerCapabilityCodec: () => ownerCapabilityCodec,
  ownerAuthorizationCodecs: () => ownerAuthorizationCodecs,
  ownerAuthorizationBundleCodec: () => ownerAuthorizationBundleCodec,
  newPasskeyOwnerRootApprovalCodec: () => newPasskeyOwnerRootApprovalCodec,
  isCanonicalProtobuf: () => isCanonicalProtobuf,
  existingPasskeyOwnerRootApprovalCodec: () => existingPasskeyOwnerRootApprovalCodec,
  deferredOwnerRootApprovalCodec: () => deferredOwnerRootApprovalCodec,
  cloneOwnerPinCodec: () => cloneOwnerPinCodec,
  cloneAuthorizationKeyringCodec: () => cloneAuthorizationKeyringCodec,
  capabilityPrincipalCodec: () => capabilityPrincipalCodec,
  bytesEqual: () => bytesEqual,
  bootstrapOwnerRootResponseCodec: () => bootstrapOwnerRootResponseCodec,
  bootstrapOwnerRootRequestCodec: () => bootstrapOwnerRootRequestCodec,
  authorizationVerificationKeyCodec: () => authorizationVerificationKeyCodec,
  authorizationSignatureCodec: () => authorizationSignatureCodec,
  anonymousKeyCredentialCodec: () => anonymousKeyCredentialCodec,
  ProtoWriter: () => ProtoWriter,
  ProtoReader: () => ProtoReader
});
class ProtoWriter {
  #bytes = [];
  uint32(field, value) {
    if (value !== 0)
      this.varint(field, BigInt(value >>> 0));
  }
  enum(field, value) {
    if (value !== 0)
      this.varint(field, BigInt(value));
  }
  uint64(field, value) {
    if (value !== 0n)
      this.varint(field, value);
  }
  int64(field, value) {
    if (value !== 0n)
      this.varint(field, BigInt.asUintN(64, value));
  }
  bool(field, value) {
    if (value)
      this.varint(field, 1n);
  }
  bytes(field, value, force = false) {
    if (!force && value.byteLength === 0)
      return;
    this.#tag(field, 2);
    this.#pushVarint(BigInt(value.byteLength));
    this.#bytes.push(...value);
  }
  string(field, value, force = false) {
    if (!force && value.length === 0)
      return;
    this.bytes(field, new TextEncoder().encode(value), force);
  }
  message(field, value, codec) {
    if (value !== undefined)
      this.bytes(field, codec.encode(value), true);
  }
  packedEnums(field, values) {
    if (values.length === 0)
      return;
    const packed = new ProtoWriter;
    for (const value of values)
      packed.#pushVarint(BigInt(value));
    this.bytes(field, packed.finish(), true);
  }
  finish() {
    return new Uint8Array(this.#bytes);
  }
  varint(field, value) {
    if (value < 0n)
      fail("INVALID", "protobuf varint cannot be negative");
    this.#tag(field, 0);
    this.#pushVarint(value);
  }
  #tag(field, wire) {
    if (!Number.isInteger(field) || field <= 0) {
      fail("INVALID", "protobuf field number is invalid");
    }
    this.#pushVarint(BigInt(field << 3 | wire));
  }
  #pushVarint(input) {
    let value = input;
    while (value > 0x7fn) {
      this.#bytes.push(Number(value & 0x7fn | 0x80n));
      value >>= 7n;
    }
    this.#bytes.push(Number(value));
  }
}

class ProtoReader {
  input;
  #position = 0;
  constructor(input) {
    this.input = input;
  }
  get done() {
    return this.#position === this.input.byteLength;
  }
  tag() {
    const value = this.varint();
    const number = Number(value);
    const field = number >>> 3;
    const wire = number & 7;
    if (!Number.isSafeInteger(number) || field === 0 || ![0, 1, 2, 5].includes(wire)) {
      fail("INVALID", "invalid protobuf tag");
    }
    return { field, wire };
  }
  varint() {
    let value = 0n;
    let shift = 0n;
    for (let count = 0;count < 10; count++) {
      if (this.#position >= this.input.byteLength) {
        fail("INVALID", "truncated protobuf varint");
      }
      const byte = this.input[this.#position++];
      value |= BigInt(byte & 127) << shift;
      if ((byte & 128) === 0)
        return value;
      shift += 7n;
    }
    fail("INVALID", "protobuf varint is too long");
  }
  number() {
    const value = Number(this.varint());
    if (!Number.isSafeInteger(value)) {
      fail("INVALID", "protobuf integer exceeds JavaScript safe range");
    }
    return value;
  }
  int64() {
    return BigInt.asIntN(64, this.varint());
  }
  bytes() {
    const length = this.number();
    const end = this.#position + length;
    if (end > this.input.byteLength) {
      fail("INVALID", "truncated protobuf bytes");
    }
    const value = this.input.slice(this.#position, end);
    this.#position = end;
    return value;
  }
  string() {
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(this.bytes());
    } catch {
      fail("INVALID", "protobuf string is not valid UTF-8");
    }
  }
  skip(wire) {
    if (wire === 0) {
      this.varint();
    } else if (wire === 1) {
      this.#advance(8);
    } else if (wire === 2) {
      this.#advance(this.number());
    } else if (wire === 5) {
      this.#advance(4);
    }
  }
  #advance(length) {
    this.#position += length;
    if (this.#position > this.input.byteLength) {
      fail("INVALID", "truncated protobuf field");
    }
  }
}
function codec(encode, decode) {
  return {
    encode(value) {
      const writer = new ProtoWriter;
      encode(value, writer);
      return writer.finish();
    },
    decode(bytes) {
      return decode(new ProtoReader(bytes));
    }
  };
}
function eachField(reader, visit) {
  while (!reader.done) {
    const { field, wire } = reader.tag();
    if (!visit(field, wire))
      reader.skip(wire);
  }
}
function requireWire(actual, expected, field) {
  if (actual !== expected) {
    fail("INVALID", `${field} has the wrong protobuf wire type`);
  }
}
function message(reader, wire, field, valueCodec) {
  requireWire(wire, 2, field);
  return valueCodec.decode(reader.bytes());
}
function bytes(reader, wire, field) {
  requireWire(wire, 2, field);
  return reader.bytes();
}
function string(reader, wire, field) {
  requireWire(wire, 2, field);
  return reader.string();
}
function number(reader, wire, field) {
  requireWire(wire, 0, field);
  return reader.number();
}
function int64(reader, wire, field) {
  requireWire(wire, 0, field);
  return reader.int64();
}
function uint64(reader, wire, field) {
  requireWire(wire, 0, field);
  return reader.varint();
}
var authorizationVerificationKeyCodec = codec((value, writer) => {
  writer.enum(1, value.algorithm);
  writer.bytes(2, value.publicKey);
}, (reader) => {
  let algorithm = 0;
  let publicKey = new Uint8Array;
  eachField(reader, (field, wire) => {
    if (field === 1)
      algorithm = number(reader, wire, "key.algorithm");
    else if (field === 2) {
      publicKey = bytes(reader, wire, "key.public_key");
    } else
      return false;
    return true;
  });
  return { algorithm, publicKey };
});
var authorizationSignatureCodec = codec((value, writer) => {
  writer.bytes(1, value.signerKeyId);
  writer.bytes(2, value.signature);
}, (reader) => {
  let signerKeyId = new Uint8Array;
  let signature = new Uint8Array;
  eachField(reader, (field, wire) => {
    if (field === 1) {
      signerKeyId = bytes(reader, wire, "signature.signer_key_id");
    } else if (field === 2) {
      signature = bytes(reader, wire, "signature.signature");
    } else
      return false;
    return true;
  });
  return { signerKeyId, signature };
});
var recoveryGuardianCodec = codec((value, writer) => {
  writer.enum(1, value.kind);
  writer.message(2, value.key, authorizationVerificationKeyCodec);
}, (reader) => {
  let kind = 0;
  let key;
  eachField(reader, (field, wire) => {
    if (field === 1)
      kind = number(reader, wire, "guardian.kind");
    else if (field === 2) {
      key = message(reader, wire, "guardian.key", authorizationVerificationKeyCodec);
    } else
      return false;
    return true;
  });
  return { kind, key };
});
var recoveryPolicyCodec = codec((value, writer) => {
  writer.uint32(1, value.threshold);
  for (const guardian of value.guardians) {
    writer.message(2, guardian, recoveryGuardianCodec);
  }
}, (reader) => {
  let threshold = 0;
  const guardians = [];
  eachField(reader, (field, wire) => {
    if (field === 1)
      threshold = number(reader, wire, "policy.threshold");
    else if (field === 2) {
      guardians.push(message(reader, wire, "policy.guardians", recoveryGuardianCodec));
    } else
      return false;
    return true;
  });
  return { threshold, guardians };
});
var ownerRootCodec = codec((value, writer) => {
  writer.uint32(1, value.formatVersion);
  writer.bytes(2, value.ownerId);
  writer.bytes(3, value.accountUuid);
  writer.message(4, value.authorityKey, authorizationVerificationKeyCodec);
  writer.message(5, value.recoveryPolicy, recoveryPolicyCodec);
  writer.bool(6, value.claimableDeferredHuman);
  writer.bytes(7, value.nonce);
  writer.int64(8, value.claimableUntilUnixSeconds);
}, (reader) => {
  const value = {
    formatVersion: 0,
    ownerId: new Uint8Array,
    accountUuid: new Uint8Array,
    claimableDeferredHuman: false,
    nonce: new Uint8Array,
    claimableUntilUnixSeconds: 0n
  };
  eachField(reader, (field, wire) => {
    if (field === 1)
      value.formatVersion = number(reader, wire, "root.format_version");
    else if (field === 2)
      value.ownerId = bytes(reader, wire, "root.owner_id");
    else if (field === 3)
      value.accountUuid = bytes(reader, wire, "root.account_uuid");
    else if (field === 4) {
      value.authorityKey = message(reader, wire, "root.authority_key", authorizationVerificationKeyCodec);
    } else if (field === 5) {
      value.recoveryPolicy = message(reader, wire, "root.recovery_policy", recoveryPolicyCodec);
    } else if (field === 6) {
      value.claimableDeferredHuman = number(reader, wire, "root.claimable_deferred_human") !== 0;
    } else if (field === 7)
      value.nonce = bytes(reader, wire, "root.nonce");
    else if (field === 8) {
      value.claimableUntilUnixSeconds = int64(reader, wire, "root.claimable_until_unix_seconds");
    } else
      return false;
    return true;
  });
  return value;
});
var signedOwnerRootCodec = codec((value, writer) => {
  writer.message(1, value.root, ownerRootCodec);
  writer.message(2, value.authorityProof, authorizationSignatureCodec);
  for (const proof of value.recoveryKeyProofs) {
    writer.message(3, proof, authorizationSignatureCodec);
  }
}, (reader) => {
  const value = { recoveryKeyProofs: [] };
  eachField(reader, (field, wire) => {
    if (field === 1)
      value.root = message(reader, wire, "signed_root.root", ownerRootCodec);
    else if (field === 2) {
      value.authorityProof = message(reader, wire, "signed_root.authority_proof", authorizationSignatureCodec);
    } else if (field === 3) {
      value.recoveryKeyProofs.push(message(reader, wire, "signed_root.recovery_key_proofs", authorizationSignatureCodec));
    } else
      return false;
    return true;
  });
  return value;
});
var newPasskeyOwnerRootApprovalCodec = codec((value, writer) => {
  writer.bytes(1, value.clientDataJson);
  writer.bytes(2, value.attestationObject);
}, (reader) => {
  let clientDataJson = new Uint8Array;
  let attestationObject = new Uint8Array;
  eachField(reader, (field, wire) => {
    if (field === 1)
      clientDataJson = bytes(reader, wire, "new_passkey.client_data_json");
    else if (field === 2) {
      attestationObject = bytes(reader, wire, "new_passkey.attestation_object");
    } else
      return false;
    return true;
  });
  return { clientDataJson, attestationObject };
});
var existingPasskeyOwnerRootApprovalCodec = codec((value, writer) => {
  writer.bytes(1, value.credentialId);
  writer.bytes(2, value.clientDataJson);
  writer.bytes(3, value.authenticatorData);
  writer.bytes(4, value.signature);
}, (reader) => {
  const value = {
    credentialId: new Uint8Array,
    clientDataJson: new Uint8Array,
    authenticatorData: new Uint8Array,
    signature: new Uint8Array
  };
  eachField(reader, (field, wire) => {
    if (field === 1)
      value.credentialId = bytes(reader, wire, "passkey.credential_id");
    else if (field === 2)
      value.clientDataJson = bytes(reader, wire, "passkey.client_data_json");
    else if (field === 3) {
      value.authenticatorData = bytes(reader, wire, "passkey.authenticator_data");
    } else if (field === 4)
      value.signature = bytes(reader, wire, "passkey.signature");
    else
      return false;
    return true;
  });
  return value;
});
var webAuthnOwnerRootApprovalCodec = codec((value, writer) => {
  writer.string(1, value.challengeId);
  if (value.proof?.case === "newPasskey") {
    writer.message(2, value.proof.value, newPasskeyOwnerRootApprovalCodec);
  } else if (value.proof?.case === "existingPasskey") {
    writer.message(3, value.proof.value, existingPasskeyOwnerRootApprovalCodec);
  }
}, (reader) => {
  const value = {
    challengeId: "",
    proof: undefined
  };
  eachField(reader, (field, wire) => {
    if (field === 1)
      value.challengeId = string(reader, wire, "approval.challenge_id");
    else if (field === 2) {
      value.proof = {
        case: "newPasskey",
        value: message(reader, wire, "approval.new_passkey", newPasskeyOwnerRootApprovalCodec)
      };
    } else if (field === 3) {
      value.proof = {
        case: "existingPasskey",
        value: message(reader, wire, "approval.existing_passkey", existingPasskeyOwnerRootApprovalCodec)
      };
    } else
      return false;
    return true;
  });
  return value;
});
var ownerKeyTransitionCodec = codec((value, writer) => {
  writer.uint32(1, value.formatVersion);
  writer.bytes(2, value.ownerId);
  writer.bytes(3, value.previousStateHash);
  writer.uint64(4, value.sequence);
  writer.enum(5, value.kind);
  writer.message(6, value.nextAuthorityKey, authorizationVerificationKeyCodec);
  writer.message(7, value.nextRecoveryPolicy, recoveryPolicyCodec);
  writer.int64(8, value.validFromUnixSeconds);
  writer.int64(9, value.previousKeyValidUntilUnixSeconds);
  writer.bytes(10, value.nonce);
}, (reader) => {
  const value = {
    formatVersion: 0,
    ownerId: new Uint8Array,
    previousStateHash: new Uint8Array,
    sequence: 0n,
    kind: 0,
    validFromUnixSeconds: 0n,
    previousKeyValidUntilUnixSeconds: 0n,
    nonce: new Uint8Array
  };
  eachField(reader, (field, wire) => {
    if (field === 1)
      value.formatVersion = number(reader, wire, "transition.format_version");
    else if (field === 2)
      value.ownerId = bytes(reader, wire, "transition.owner_id");
    else if (field === 3) {
      value.previousStateHash = bytes(reader, wire, "transition.previous_state_hash");
    } else if (field === 4)
      value.sequence = uint64(reader, wire, "transition.sequence");
    else if (field === 5)
      value.kind = number(reader, wire, "transition.kind");
    else if (field === 6) {
      value.nextAuthorityKey = message(reader, wire, "transition.next_authority_key", authorizationVerificationKeyCodec);
    } else if (field === 7) {
      value.nextRecoveryPolicy = message(reader, wire, "transition.next_recovery_policy", recoveryPolicyCodec);
    } else if (field === 8) {
      value.validFromUnixSeconds = int64(reader, wire, "transition.valid_from");
    } else if (field === 9) {
      value.previousKeyValidUntilUnixSeconds = int64(reader, wire, "transition.previous_key_valid_until");
    } else if (field === 10)
      value.nonce = bytes(reader, wire, "transition.nonce");
    else
      return false;
    return true;
  });
  return value;
});
var signedOwnerKeyTransitionCodec = codec((value, writer) => {
  writer.message(1, value.transition, ownerKeyTransitionCodec);
  for (const signature of value.authorizations) {
    writer.message(2, signature, authorizationSignatureCodec);
  }
  writer.message(3, value.nextAuthorityKeyProof, authorizationSignatureCodec);
  for (const proof of value.nextRecoveryKeyProofs) {
    writer.message(4, proof, authorizationSignatureCodec);
  }
}, (reader) => {
  const value = {
    authorizations: [],
    nextRecoveryKeyProofs: []
  };
  eachField(reader, (field, wire) => {
    if (field === 1) {
      value.transition = message(reader, wire, "signed_transition.transition", ownerKeyTransitionCodec);
    } else if (field === 2) {
      value.authorizations.push(message(reader, wire, "signed_transition.authorizations", authorizationSignatureCodec));
    } else if (field === 3) {
      value.nextAuthorityKeyProof = message(reader, wire, "signed_transition.next_authority_key_proof", authorizationSignatureCodec);
    } else if (field === 4) {
      value.nextRecoveryKeyProofs.push(message(reader, wire, "signed_transition.next_recovery_key_proofs", authorizationSignatureCodec));
    } else
      return false;
    return true;
  });
  return value;
});
var spoolSelectorCodec = codec((value, writer) => {
  writer.bytes(1, value.rootSpoolUuid);
  for (const segment of value.pathSegments)
    writer.string(2, segment, true);
  writer.bool(3, value.includeDescendants);
}, (reader) => {
  const value = {
    rootSpoolUuid: new Uint8Array,
    pathSegments: [],
    includeDescendants: false
  };
  eachField(reader, (field, wire) => {
    if (field === 1)
      value.rootSpoolUuid = bytes(reader, wire, "selector.root_spool_uuid");
    else if (field === 2)
      value.pathSegments.push(string(reader, wire, "selector.path_segments"));
    else if (field === 3) {
      value.includeDescendants = number(reader, wire, "selector.include_descendants") !== 0;
    } else
      return false;
    return true;
  });
  return value;
});
var capabilityPrincipalCodec = codec((value, writer) => {
  writer.enum(1, value.kind);
  writer.bytes(2, value.principalId);
  writer.message(3, value.key, authorizationVerificationKeyCodec);
}, (reader) => {
  const value = {
    kind: 0,
    principalId: new Uint8Array
  };
  eachField(reader, (field, wire) => {
    if (field === 1)
      value.kind = number(reader, wire, "principal.kind");
    else if (field === 2)
      value.principalId = bytes(reader, wire, "principal.principal_id");
    else if (field === 3) {
      value.key = message(reader, wire, "principal.key", authorizationVerificationKeyCodec);
    } else
      return false;
    return true;
  });
  return value;
});
var spoolCapabilityGrantCodec = codec((value, writer) => {
  writer.message(1, value.spool, spoolSelectorCodec);
  writer.packedEnums(2, value.actions);
}, (reader) => {
  const value = { actions: [] };
  eachField(reader, (field, wire) => {
    if (field === 1) {
      value.spool = message(reader, wire, "grant.spool", spoolSelectorCodec);
    } else if (field === 2 && wire === 2) {
      const packed = new ProtoReader(reader.bytes());
      while (!packed.done)
        value.actions.push(packed.number());
    } else if (field === 2 && wire === 0) {
      value.actions.push(reader.number());
    } else
      return false;
    return true;
  });
  return value;
});
var ownerCapabilityCodec = codec((value, writer) => {
  writer.uint32(1, value.formatVersion);
  writer.bytes(2, value.ownerId);
  writer.bytes(3, value.issuerStateHash);
  writer.bytes(4, value.parentCapabilityId);
  writer.message(5, value.subject, capabilityPrincipalCodec);
  for (const grant of value.grants)
    writer.message(6, grant, spoolCapabilityGrantCodec);
  writer.int64(7, value.notBeforeUnixSeconds);
  writer.int64(8, value.expiresAtUnixSeconds);
  writer.bytes(9, value.nonce);
  writer.bytes(10, value.capabilityId);
}, (reader) => {
  const value = {
    formatVersion: 0,
    ownerId: new Uint8Array,
    issuerStateHash: new Uint8Array,
    parentCapabilityId: new Uint8Array,
    grants: [],
    notBeforeUnixSeconds: 0n,
    expiresAtUnixSeconds: 0n,
    nonce: new Uint8Array,
    capabilityId: new Uint8Array
  };
  eachField(reader, (field, wire) => {
    if (field === 1)
      value.formatVersion = number(reader, wire, "capability.format_version");
    else if (field === 2)
      value.ownerId = bytes(reader, wire, "capability.owner_id");
    else if (field === 3) {
      value.issuerStateHash = bytes(reader, wire, "capability.issuer_state_hash");
    } else if (field === 4) {
      value.parentCapabilityId = bytes(reader, wire, "capability.parent_capability_id");
    } else if (field === 5) {
      value.subject = message(reader, wire, "capability.subject", capabilityPrincipalCodec);
    } else if (field === 6) {
      value.grants.push(message(reader, wire, "capability.grants", spoolCapabilityGrantCodec));
    } else if (field === 7) {
      value.notBeforeUnixSeconds = int64(reader, wire, "capability.not_before");
    } else if (field === 8) {
      value.expiresAtUnixSeconds = int64(reader, wire, "capability.expires_at");
    } else if (field === 9)
      value.nonce = bytes(reader, wire, "capability.nonce");
    else if (field === 10) {
      value.capabilityId = bytes(reader, wire, "capability.capability_id");
    } else
      return false;
    return true;
  });
  return value;
});
var signedOwnerCapabilityCodec = codec((value, writer) => {
  writer.message(1, value.capability, ownerCapabilityCodec);
  writer.message(2, value.signature, authorizationSignatureCodec);
}, (reader) => {
  const value = {};
  eachField(reader, (field, wire) => {
    if (field === 1) {
      value.capability = message(reader, wire, "signed_capability.capability", ownerCapabilityCodec);
    } else if (field === 2) {
      value.signature = message(reader, wire, "signed_capability.signature", authorizationSignatureCodec);
    } else
      return false;
    return true;
  });
  return value;
});
var ownerAuthorizationBundleCodec = codec((value, writer) => {
  writer.message(1, value.ownerRoot, signedOwnerRootCodec);
  for (const transition of value.ownerStateChain) {
    writer.message(2, transition, signedOwnerKeyTransitionCodec);
  }
  for (const capability of value.capabilityChain) {
    writer.message(3, capability, signedOwnerCapabilityCodec);
  }
  writer.bytes(4, value.subjectBiscuit);
}, (reader) => {
  const value = {
    ownerStateChain: [],
    capabilityChain: [],
    subjectBiscuit: new Uint8Array
  };
  eachField(reader, (field, wire) => {
    if (field === 1) {
      value.ownerRoot = message(reader, wire, "bundle.owner_root", signedOwnerRootCodec);
    } else if (field === 2) {
      value.ownerStateChain.push(message(reader, wire, "bundle.owner_state_chain", signedOwnerKeyTransitionCodec));
    } else if (field === 3) {
      value.capabilityChain.push(message(reader, wire, "bundle.capability_chain", signedOwnerCapabilityCodec));
    } else if (field === 4) {
      value.subjectBiscuit = bytes(reader, wire, "bundle.subject_biscuit");
    } else
      return false;
    return true;
  });
  return value;
});
var deferredOwnerRootApprovalCodec = codec((value, writer) => {
  writer.message(1, value.provisioningAuthority, ownerAuthorizationBundleCodec);
  writer.message(2, value.originKeyRequestSignature, authorizationSignatureCodec);
}, (reader) => {
  const value = {};
  eachField(reader, (field, wire) => {
    if (field === 1) {
      value.provisioningAuthority = message(reader, wire, "deferred.provisioning_authority", ownerAuthorizationBundleCodec);
    } else if (field === 2) {
      value.originKeyRequestSignature = message(reader, wire, "deferred.origin_key_request_signature", authorizationSignatureCodec);
    } else
      return false;
    return true;
  });
  return value;
});
var bootstrapOwnerRootRequestCodec = codec((value, writer) => {
  writer.message(1, value.ownerRoot, signedOwnerRootCodec);
  if (value.approval?.case === "human") {
    writer.message(2, value.approval.value, webAuthnOwnerRootApprovalCodec);
  } else if (value.approval?.case === "deferredHuman") {
    writer.message(3, value.approval.value, deferredOwnerRootApprovalCodec);
  }
  writer.string(4, value.clientOperationId);
}, (reader) => {
  const value = {
    approval: undefined,
    clientOperationId: ""
  };
  eachField(reader, (field, wire) => {
    if (field === 1) {
      value.ownerRoot = message(reader, wire, "bootstrap.owner_root", signedOwnerRootCodec);
    } else if (field === 2) {
      value.approval = {
        case: "human",
        value: message(reader, wire, "bootstrap.human", webAuthnOwnerRootApprovalCodec)
      };
    } else if (field === 3) {
      value.approval = {
        case: "deferredHuman",
        value: message(reader, wire, "bootstrap.deferred_human", deferredOwnerRootApprovalCodec)
      };
    } else if (field === 4) {
      value.clientOperationId = string(reader, wire, "bootstrap.client_operation_id");
    } else
      return false;
    return true;
  });
  return value;
});
var bootstrapOwnerRootResponseCodec = codec((value, writer) => {
  writer.bytes(1, value.ownerId);
  writer.bytes(2, value.acceptedRootHash);
}, (reader) => {
  let ownerId = new Uint8Array;
  let acceptedRootHash = new Uint8Array;
  eachField(reader, (field, wire) => {
    if (field === 1)
      ownerId = bytes(reader, wire, "bootstrap_response.owner_id");
    else if (field === 2) {
      acceptedRootHash = bytes(reader, wire, "bootstrap_response.accepted_root_hash");
    } else
      return false;
    return true;
  });
  return { ownerId, acceptedRootHash };
});
var submitOwnerAuthorizationRequestCodec = codec((value, writer) => {
  writer.message(1, value.authorization, ownerAuthorizationBundleCodec);
  writer.string(2, value.clientOperationId);
}, (reader) => {
  const value = { clientOperationId: "" };
  eachField(reader, (field, wire) => {
    if (field === 1) {
      value.authorization = message(reader, wire, "submit.authorization", ownerAuthorizationBundleCodec);
    } else if (field === 2) {
      value.clientOperationId = string(reader, wire, "submit.client_operation_id");
    } else
      return false;
    return true;
  });
  return value;
});
var submitOwnerAuthorizationResponseCodec = codec((value, writer) => {
  writer.bytes(1, value.capabilityId);
  writer.int64(2, value.expiresAtUnixSeconds);
}, (reader) => {
  let capabilityId = new Uint8Array;
  let expiresAtUnixSeconds = 0n;
  eachField(reader, (field, wire) => {
    if (field === 1)
      capabilityId = bytes(reader, wire, "submit_response.capability_id");
    else if (field === 2) {
      expiresAtUnixSeconds = int64(reader, wire, "submit_response.expires_at_unix_seconds");
    } else
      return false;
    return true;
  });
  return { capabilityId, expiresAtUnixSeconds };
});
var anonymousKeyCredentialCodec = codec((value, writer) => {
  writer.uint32(1, value.formatVersion);
  writer.bytes(2, value.anonymousId);
  writer.message(3, value.key, authorizationVerificationKeyCodec);
  writer.int64(4, value.issuedAtUnixSeconds);
  writer.int64(5, value.expiresAtUnixSeconds);
  writer.bytes(6, value.nonce);
  writer.message(7, value.selfSignature, authorizationSignatureCodec);
}, (reader) => {
  const value = {
    formatVersion: 0,
    anonymousId: new Uint8Array,
    issuedAtUnixSeconds: 0n,
    expiresAtUnixSeconds: 0n,
    nonce: new Uint8Array
  };
  eachField(reader, (field, wire) => {
    if (field === 1)
      value.formatVersion = number(reader, wire, "anonymous.format_version");
    else if (field === 2)
      value.anonymousId = bytes(reader, wire, "anonymous.anonymous_id");
    else if (field === 3) {
      value.key = message(reader, wire, "anonymous.key", authorizationVerificationKeyCodec);
    } else if (field === 4) {
      value.issuedAtUnixSeconds = int64(reader, wire, "anonymous.issued_at");
    } else if (field === 5) {
      value.expiresAtUnixSeconds = int64(reader, wire, "anonymous.expires_at");
    } else if (field === 6)
      value.nonce = bytes(reader, wire, "anonymous.nonce");
    else if (field === 7) {
      value.selfSignature = message(reader, wire, "anonymous.self_signature", authorizationSignatureCodec);
    } else
      return false;
    return true;
  });
  return value;
});
var registerAnonymousKeyRequestCodec = codec((value, writer) => {
  writer.message(1, value.credential, anonymousKeyCredentialCodec);
  if (value.turnstileToken !== undefined) {
    writer.string(2, value.turnstileToken, true);
  }
  writer.string(3, value.priorContinuityToken);
  writer.message(4, value.continuityProof, authorizationSignatureCodec);
  writer.string(5, value.clientOperationId);
}, (reader) => {
  const value = {
    priorContinuityToken: "",
    clientOperationId: ""
  };
  eachField(reader, (field, wire) => {
    if (field === 1) {
      value.credential = message(reader, wire, "registration.credential", anonymousKeyCredentialCodec);
    } else if (field === 2) {
      value.turnstileToken = string(reader, wire, "registration.turnstile_token");
    } else if (field === 3) {
      value.priorContinuityToken = string(reader, wire, "registration.prior_continuity_token");
    } else if (field === 4) {
      value.continuityProof = message(reader, wire, "registration.continuity_proof", authorizationSignatureCodec);
    } else if (field === 5) {
      value.clientOperationId = string(reader, wire, "registration.client_operation_id");
    } else
      return false;
    return true;
  });
  return value;
});
var registerAnonymousKeyResponseCodec = codec((value, writer) => {
  writer.bytes(1, value.anonymousId);
  writer.string(2, value.continuityToken);
  writer.int64(3, value.continuityExpiresAtUnixSeconds);
}, (reader) => {
  let anonymousId = new Uint8Array;
  let continuityToken = "";
  let continuityExpiresAtUnixSeconds = 0n;
  eachField(reader, (field, wire) => {
    if (field === 1) {
      anonymousId = bytes(reader, wire, "registration_response.anonymous_id");
    } else if (field === 2) {
      continuityToken = string(reader, wire, "registration_response.continuity_token");
    } else if (field === 3) {
      continuityExpiresAtUnixSeconds = int64(reader, wire, "registration_response.continuity_expires_at");
    } else
      return false;
    return true;
  });
  return {
    anonymousId,
    continuityToken,
    continuityExpiresAtUnixSeconds
  };
});
var cloneOwnerPinCodec = codec((value, writer) => {
  writer.enum(1, value.kind);
  writer.bytes(2, value.expectedOwnerId);
  writer.int64(3, value.firstSeenUnixSeconds);
}, (reader) => {
  const value = {
    kind: 0,
    expectedOwnerId: new Uint8Array,
    firstSeenUnixSeconds: 0n
  };
  eachField(reader, (field, wire) => {
    if (field === 1)
      value.kind = number(reader, wire, "pin.kind");
    else if (field === 2) {
      value.expectedOwnerId = bytes(reader, wire, "pin.expected_owner_id");
    } else if (field === 3) {
      value.firstSeenUnixSeconds = int64(reader, wire, "pin.first_seen");
    } else
      return false;
    return true;
  });
  return value;
});
var cloneAuthorizationKeyringCodec = codec((value, writer) => {
  writer.uint32(1, value.formatVersion);
  writer.bytes(2, value.spoolUuid);
  for (const segment of value.canonicalSpoolPathSegments) {
    writer.string(3, segment, true);
  }
  writer.message(4, value.pin, cloneOwnerPinCodec);
  writer.message(5, value.ownerRoot, signedOwnerRootCodec);
  for (const transition of value.acceptedTransitions) {
    writer.message(6, transition, signedOwnerKeyTransitionCodec);
  }
  writer.bytes(7, value.acceptedStateHash);
  for (const capability of value.publicAccessCapabilities) {
    writer.message(8, capability, signedOwnerCapabilityCodec);
  }
}, (reader) => {
  const value = {
    formatVersion: 0,
    spoolUuid: new Uint8Array,
    canonicalSpoolPathSegments: [],
    acceptedTransitions: [],
    acceptedStateHash: new Uint8Array,
    publicAccessCapabilities: []
  };
  eachField(reader, (field, wire) => {
    if (field === 1)
      value.formatVersion = number(reader, wire, "keyring.format_version");
    else if (field === 2)
      value.spoolUuid = bytes(reader, wire, "keyring.spool_uuid");
    else if (field === 3) {
      value.canonicalSpoolPathSegments.push(string(reader, wire, "keyring.canonical_spool_path_segments"));
    } else if (field === 4) {
      value.pin = message(reader, wire, "keyring.pin", cloneOwnerPinCodec);
    } else if (field === 5) {
      value.ownerRoot = message(reader, wire, "keyring.owner_root", signedOwnerRootCodec);
    } else if (field === 6) {
      value.acceptedTransitions.push(message(reader, wire, "keyring.accepted_transitions", signedOwnerKeyTransitionCodec));
    } else if (field === 7) {
      value.acceptedStateHash = bytes(reader, wire, "keyring.accepted_state_hash");
    } else if (field === 8) {
      value.publicAccessCapabilities.push(message(reader, wire, "keyring.public_access_capabilities", signedOwnerCapabilityCodec));
    } else
      return false;
    return true;
  });
  return value;
});
var ownerAuthorizationCodecs = {
  authorizationVerificationKey: authorizationVerificationKeyCodec,
  authorizationSignature: authorizationSignatureCodec,
  recoveryGuardian: recoveryGuardianCodec,
  recoveryPolicy: recoveryPolicyCodec,
  ownerRoot: ownerRootCodec,
  signedOwnerRoot: signedOwnerRootCodec,
  newPasskeyOwnerRootApproval: newPasskeyOwnerRootApprovalCodec,
  existingPasskeyOwnerRootApproval: existingPasskeyOwnerRootApprovalCodec,
  webAuthnOwnerRootApproval: webAuthnOwnerRootApprovalCodec,
  deferredOwnerRootApproval: deferredOwnerRootApprovalCodec,
  bootstrapOwnerRootRequest: bootstrapOwnerRootRequestCodec,
  bootstrapOwnerRootResponse: bootstrapOwnerRootResponseCodec,
  ownerKeyTransition: ownerKeyTransitionCodec,
  signedOwnerKeyTransition: signedOwnerKeyTransitionCodec,
  spoolSelector: spoolSelectorCodec,
  capabilityPrincipal: capabilityPrincipalCodec,
  spoolCapabilityGrant: spoolCapabilityGrantCodec,
  ownerCapability: ownerCapabilityCodec,
  signedOwnerCapability: signedOwnerCapabilityCodec,
  ownerAuthorizationBundle: ownerAuthorizationBundleCodec,
  submitOwnerAuthorizationRequest: submitOwnerAuthorizationRequestCodec,
  submitOwnerAuthorizationResponse: submitOwnerAuthorizationResponseCodec,
  anonymousKeyCredential: anonymousKeyCredentialCodec,
  registerAnonymousKeyRequest: registerAnonymousKeyRequestCodec,
  registerAnonymousKeyResponse: registerAnonymousKeyResponseCodec,
  cloneOwnerPin: cloneOwnerPinCodec,
  cloneAuthorizationKeyring: cloneAuthorizationKeyringCodec
};
function isCanonicalProtobuf(bytesValue, valueCodec) {
  const decoded = valueCodec.decode(bytesValue);
  return bytesEqual(valueCodec.encode(decoded), bytesValue);
}
function bytesEqual(left, right) {
  return left.byteLength === right.byteLength && left.every((value, index) => value === right[index]);
}

// src/lib/owner-authorization/canonical.ts
var OWNER_ROOT_DOMAIN = utf8("heddle-owner-root-v1");
var OWNER_TRANSITION_DOMAIN = utf8("heddle-owner-key-transition-v1");
var OWNER_CAPABILITY_DOMAIN = utf8("heddle-owner-capability-v1");
var ANONYMOUS_ID_DOMAIN = utf8("heddle-anonymous-v1");
var ANONYMOUS_CREDENTIAL_DOMAIN = utf8("heddle-anonymous-key-credential-v1");
var ANONYMOUS_REGISTRATION_DOMAIN = utf8("heddle-anonymous-registration-v1");
var DEFERRED_BOOTSTRAP_DOMAIN = utf8("heddle-owner-deferred-bootstrap-v1");
var BOOTSTRAP_CHALLENGE_DOMAIN = utf8("heddle-owner-bootstrap-v1");
var KEY_ID_DOMAIN = utf8("heddle-key-v1");

class CanonicalWriter {
  #parts = [];
  bool(value) {
    this.#parts.push(Uint8Array.of(value ? 1 : 0));
  }
  u32(value) {
    if (!Number.isInteger(value) || value < 0 || value > 4294967295) {
      fail("INVALID", "canonical u32 is out of range");
    }
    const bytes2 = new Uint8Array(4);
    new DataView(bytes2.buffer).setUint32(0, value, false);
    this.#parts.push(bytes2);
  }
  i32(value) {
    if (!Number.isInteger(value) || value < -2147483648 || value > 2147483647) {
      fail("INVALID", "canonical i32 is out of range");
    }
    const bytes2 = new Uint8Array(4);
    new DataView(bytes2.buffer).setInt32(0, value, false);
    this.#parts.push(bytes2);
  }
  u64(value) {
    if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
      fail("INVALID", "canonical u64 is out of range");
    }
    const bytes2 = new Uint8Array(8);
    new DataView(bytes2.buffer).setBigUint64(0, value, false);
    this.#parts.push(bytes2);
  }
  i64(value) {
    if (value < -0x8000_0000_0000_0000n || value > 0x7fff_ffff_ffff_ffffn) {
      fail("INVALID", "canonical i64 is out of range");
    }
    const bytes2 = new Uint8Array(8);
    new DataView(bytes2.buffer).setBigInt64(0, value, false);
    this.#parts.push(bytes2);
  }
  bytes(value) {
    this.u32(value.byteLength);
    this.#parts.push(value);
  }
  string(value) {
    this.bytes(utf8(value));
  }
  count(value) {
    this.u32(value);
  }
  finish() {
    return concatBytes(...this.#parts);
  }
}
async function sha256(...parts) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", concatBytes(...parts)));
}
async function digest(domain, body) {
  return sha256(domain, body);
}
async function keyId(key) {
  const algorithm = new Uint8Array(4);
  new DataView(algorithm.buffer).setInt32(0, key.algorithm, false);
  return digest(KEY_ID_DOMAIN, concatBytes(algorithm, key.publicKey));
}
function verificationKey(writer, key) {
  writer.i32(key.algorithm);
  writer.bytes(key.publicKey);
}
async function recoveryGuardian(writer, guardian) {
  writer.i32(guardian.kind);
  verificationKey(writer, requireValue(guardian.key, "RecoveryGuardian.key"));
}
async function recoveryPolicy(writer, policy) {
  const keyed = await Promise.all(policy.guardians.map(async (guardian) => ({
    guardian,
    id: await keyId(requireValue(guardian.key, "RecoveryGuardian.key"))
  })));
  const sorted = [...keyed].sort((left, right) => compareBytes(left.id, right.id));
  if (sorted.some((entry, index) => entry.guardian !== policy.guardians[index])) {
    fail("INVALID", "recovery guardians are not sorted by key id");
  }
  writer.u32(policy.threshold);
  writer.count(sorted.length);
  for (const { guardian } of sorted) {
    await recoveryGuardian(writer, guardian);
  }
}
async function ownerRootWithoutId(root) {
  const writer = new CanonicalWriter;
  writer.u32(root.formatVersion);
  writer.bytes(root.accountUuid);
  verificationKey(writer, requireValue(root.authorityKey, "OwnerRoot.authorityKey"));
  await recoveryPolicy(writer, requireValue(root.recoveryPolicy, "OwnerRoot.recoveryPolicy"));
  writer.bool(root.claimableDeferredHuman);
  writer.bytes(root.nonce);
  writer.i64(root.claimableUntilUnixSeconds);
  return writer.finish();
}
async function ownerRootBody(root) {
  const writer = new CanonicalWriter;
  writer.u32(root.formatVersion);
  writer.bytes(root.ownerId);
  writer.bytes(root.accountUuid);
  verificationKey(writer, requireValue(root.authorityKey, "OwnerRoot.authorityKey"));
  await recoveryPolicy(writer, requireValue(root.recoveryPolicy, "OwnerRoot.recoveryPolicy"));
  writer.bool(root.claimableDeferredHuman);
  writer.bytes(root.nonce);
  writer.i64(root.claimableUntilUnixSeconds);
  return writer.finish();
}
async function transitionBody(transition) {
  const writer = new CanonicalWriter;
  writer.u32(transition.formatVersion);
  writer.bytes(transition.ownerId);
  writer.bytes(transition.previousStateHash);
  writer.u64(transition.sequence);
  writer.i32(transition.kind);
  verificationKey(writer, requireValue(transition.nextAuthorityKey, "OwnerKeyTransition.nextAuthorityKey"));
  await recoveryPolicy(writer, requireValue(transition.nextRecoveryPolicy, "OwnerKeyTransition.nextRecoveryPolicy"));
  writer.i64(transition.validFromUnixSeconds);
  writer.i64(transition.previousKeyValidUntilUnixSeconds);
  writer.bytes(transition.nonce);
  return writer.finish();
}
function selector(writer, value) {
  writer.bytes(value.rootSpoolUuid);
  writer.count(value.pathSegments.length);
  for (const segment of value.pathSegments)
    writer.string(segment);
  writer.bool(value.includeDescendants);
}
function principal(writer, value) {
  writer.i32(value.kind);
  writer.bytes(value.principalId);
  writer.bool(value.key !== undefined);
  if (value.key !== undefined)
    verificationKey(writer, value.key);
}
function grant(writer, value) {
  selector(writer, requireValue(value.spool, "SpoolCapabilityGrant.spool"));
  writer.count(value.actions.length);
  for (const action of value.actions)
    writer.i32(action);
}
async function capabilityFields(capability, includeId) {
  const writer = new CanonicalWriter;
  writer.u32(capability.formatVersion);
  writer.bytes(capability.ownerId);
  writer.bytes(capability.issuerStateHash);
  writer.bytes(capability.parentCapabilityId);
  principal(writer, requireValue(capability.subject, "OwnerCapability.subject"));
  writer.count(capability.grants.length);
  for (const capabilityGrant of capability.grants) {
    grant(writer, capabilityGrant);
  }
  writer.i64(capability.notBeforeUnixSeconds);
  writer.i64(capability.expiresAtUnixSeconds);
  writer.bytes(capability.nonce);
  if (includeId)
    writer.bytes(capability.capabilityId);
  return writer.finish();
}
function capabilityWithoutId(capability) {
  return capabilityFields(capability, false);
}
function capabilityBody(capability) {
  return capabilityFields(capability, true);
}
function anonymousBody(credential) {
  const writer = new CanonicalWriter;
  writer.u32(credential.formatVersion);
  writer.bytes(credential.anonymousId);
  verificationKey(writer, requireValue(credential.key, "AnonymousKeyCredential.key"));
  writer.i64(credential.issuedAtUnixSeconds);
  writer.i64(credential.expiresAtUnixSeconds);
  writer.bytes(credential.nonce);
  return writer.finish();
}
function registrationBody(request) {
  const writer = new CanonicalWriter;
  writer.bytes(anonymousBody(requireValue(request.credential, "RegisterAnonymousKeyRequest.credential")));
  writer.bool(request.turnstileToken !== undefined);
  if (request.turnstileToken !== undefined) {
    writer.string(request.turnstileToken);
  }
  writer.string(request.priorContinuityToken);
  writer.string(request.clientOperationId);
  return writer.finish();
}
function deferredBootstrapBody(rootHash, provisioningCapabilityId, clientOperationId) {
  const writer = new CanonicalWriter;
  writer.bytes(rootHash);
  writer.bytes(provisioningCapabilityId);
  writer.string(clientOperationId);
  return writer.finish();
}
function concatBytes(...parts) {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}
function utf8(value) {
  return new TextEncoder().encode(value);
}
function compareBytes(left, right) {
  const length = Math.min(left.byteLength, right.byteLength);
  for (let index = 0;index < length; index++) {
    if (left[index] !== right[index])
      return left[index] - right[index];
  }
  return left.byteLength - right.byteLength;
}
function includesBytes(haystack, needle) {
  if (needle.byteLength === 0)
    return true;
  for (let offset = 0;offset + needle.byteLength <= haystack.byteLength; offset++) {
    if (bytesEqual(haystack.subarray(offset, offset + needle.byteLength), needle)) {
      return true;
    }
  }
  return false;
}

// src/lib/owner-authorization/crypto.ts
var exports_crypto = {};
__export(exports_crypto, {
  verifySignature: () => verifySignature,
  signCanonical: () => signCanonical,
  signBytes: () => signBytes,
  restorePaperRecoveryKit: () => restorePaperRecoveryKit,
  randomNonce: () => randomNonce,
  generatePaperRecoveryKit: () => generatePaperRecoveryKit,
  generateAuthorizationKey: () => generateAuthorizationKey,
  authorizationKeyId: () => authorizationKeyId,
  __ownerAuthorizationCryptoTest: () => __ownerAuthorizationCryptoTest
});

// node_modules/@noble/ed25519/index.js
/*! noble-ed25519 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
var ed25519_CURVE = Object.freeze({
  p: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn,
  n: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn,
  h: 8n,
  a: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffecn,
  d: 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3n,
  Gx: 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51an,
  Gy: 0x6666666666666666666666666666666666666666666666666666666666666658n
});
var { p: P, n: N, Gx, Gy, a: _a, d: _d, h } = ed25519_CURVE;
var L = 32;
var captureTrace = (...args) => {
  if ("captureStackTrace" in Error && typeof Error.captureStackTrace === "function") {
    Error.captureStackTrace(...args);
  }
};
var err = (message2 = "") => {
  const e = new Error(message2);
  captureTrace(e, err);
  throw e;
};
var isBig = (n) => typeof n === "bigint";
var isStr = (s) => typeof s === "string";
var isBytes = (a) => a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && ("BYTES_PER_ELEMENT" in a) && a.BYTES_PER_ELEMENT === 1;
var abytes = (value, length, title = "") => {
  const bytes2 = isBytes(value);
  const len = value?.length;
  const needsLen = length !== undefined;
  if (!bytes2 || needsLen && len !== length) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : "";
    const got = bytes2 ? `length=${len}` : `type=${typeof value}`;
    const msg = prefix + "expected Uint8Array" + ofLen + ", got " + got;
    throw bytes2 ? new RangeError(msg) : new TypeError(msg);
  }
  return value;
};
var u8n = (len) => new Uint8Array(len);
var u8fr = (buf) => Uint8Array.from(buf);
var padh = (n, pad) => n.toString(16).padStart(pad, "0");
var bytesToHex = (b) => Array.from(abytes(b)).map((e) => padh(e, 2)).join("");
var C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
var _ch = (ch) => {
  if (ch >= C._0 && ch <= C._9)
    return ch - C._0;
  if (ch >= C.A && ch <= C.F)
    return ch - (C.A - 10);
  if (ch >= C.a && ch <= C.f)
    return ch - (C.a - 10);
  return;
};
var hexToBytes = (hex) => {
  const e = "hex invalid";
  if (!isStr(hex))
    return err(e);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    return err(e);
  const array = u8n(al);
  for (let ai = 0, hi = 0;ai < al; ai++, hi += 2) {
    const n1 = _ch(hex.charCodeAt(hi));
    const n2 = _ch(hex.charCodeAt(hi + 1));
    if (n1 === undefined || n2 === undefined)
      return err(e);
    array[ai] = n1 * 16 + n2;
  }
  return array;
};
var cr = () => globalThis?.crypto;
var subtle = () => cr()?.subtle ?? err("crypto.subtle must be defined, consider polyfill");
var concatBytes2 = (...arrs) => {
  let len = 0;
  for (const a of arrs)
    len += abytes(a).length;
  const r = u8n(len);
  let pad = 0;
  arrs.forEach((a) => {
    r.set(a, pad);
    pad += a.length;
  });
  return r;
};
var big = BigInt;
var assertRange = (n, min, max, msg = "bad number: out of range") => {
  if (!isBig(n))
    throw new TypeError(msg);
  if (min <= n && n < max)
    return n;
  throw new RangeError(msg);
};
var M = (a, b = P) => {
  const r = a % b;
  return r >= 0n ? r : b + r;
};
var P_MASK = (1n << 255n) - 1n;
var modP = (num) => {
  if (num < 0n)
    err("negative coordinate");
  let r = (num >> 255n) * 19n + (num & P_MASK);
  r = (r >> 255n) * 19n + (r & P_MASK);
  return r % P;
};
var modN = (a) => M(a, N);
var invert = (num, md) => {
  if (num === 0n || md <= 0n)
    err("no inverse n=" + num + " mod=" + md);
  let a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
  while (a !== 0n) {
    const q = b / a, r = b % a;
    const m = x - u * q, n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  return b === 1n ? M(x, md) : err("no inverse");
};
var callHash = (name) => {
  const fn = hashes[name];
  if (typeof fn !== "function")
    err("hashes." + name + " not set");
  return fn;
};
var checkDigest = (value) => abytes(value, 64, "digest");
var apoint = (p) => p instanceof Point ? p : err("Point expected");
var B256 = 2n ** 256n;

class Point {
  static BASE;
  static ZERO;
  X;
  Y;
  Z;
  T;
  constructor(X, Y, Z, T) {
    const max = B256;
    this.X = assertRange(X, 0n, max);
    this.Y = assertRange(Y, 0n, max);
    this.Z = assertRange(Z, 1n, max);
    this.T = assertRange(T, 0n, max);
    Object.freeze(this);
  }
  static CURVE() {
    return ed25519_CURVE;
  }
  static fromAffine(p) {
    return new Point(p.x, p.y, 1n, modP(p.x * p.y));
  }
  static fromBytes(hex, zip215 = false) {
    const d = _d;
    const normed = u8fr(abytes(hex, L));
    const lastByte = hex[31];
    normed[31] = lastByte & ~128;
    const y = bytesToNumberLE(normed);
    const max = zip215 ? B256 : P;
    assertRange(y, 0n, max);
    const y2 = modP(y * y);
    const u = M(y2 - 1n);
    const v = modP(d * y2 + 1n);
    let { isValid, value: x } = uvRatio(u, v);
    if (!isValid)
      err("bad point: y not sqrt");
    const isXOdd = (x & 1n) === 1n;
    const isLastByteOdd = (lastByte & 128) !== 0;
    if (!zip215 && x === 0n && isLastByteOdd)
      err("bad point: x==0, isLastByteOdd");
    if (isLastByteOdd !== isXOdd)
      x = M(-x);
    return new Point(x, y, 1n, modP(x * y));
  }
  static fromHex(hex, zip215) {
    return Point.fromBytes(hexToBytes(hex), zip215);
  }
  get x() {
    return this.toAffine().x;
  }
  get y() {
    return this.toAffine().y;
  }
  assertValidity() {
    const a = _a;
    const d = _d;
    const p = this;
    if (p.is0())
      return err("bad point: ZERO");
    const { X, Y, Z, T } = p;
    const X2 = modP(X * X);
    const Y2 = modP(Y * Y);
    const Z2 = modP(Z * Z);
    const Z4 = modP(Z2 * Z2);
    const aX2 = modP(X2 * a);
    const left = modP(Z2 * (aX2 + Y2));
    const right = M(Z4 + modP(d * modP(X2 * Y2)));
    if (left !== right)
      return err("bad point: equation left != right (1)");
    const XY = modP(X * Y);
    const ZT = modP(Z * T);
    if (XY !== ZT)
      return err("bad point: equation left != right (2)");
    return this;
  }
  equals(other) {
    const { X: X1, Y: Y1, Z: Z1 } = this;
    const { X: X2, Y: Y2, Z: Z2 } = apoint(other);
    const X1Z2 = modP(X1 * Z2);
    const X2Z1 = modP(X2 * Z1);
    const Y1Z2 = modP(Y1 * Z2);
    const Y2Z1 = modP(Y2 * Z1);
    return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
  }
  is0() {
    return this.equals(I);
  }
  negate() {
    return new Point(M(-this.X), this.Y, this.Z, M(-this.T));
  }
  double() {
    const { X: X1, Y: Y1, Z: Z1 } = this;
    const a = _a;
    const A = modP(X1 * X1);
    const B = modP(Y1 * Y1);
    const C2 = modP(2n * Z1 * Z1);
    const D = modP(a * A);
    const x1y1 = M(X1 + Y1);
    const E = M(modP(x1y1 * x1y1) - A - B);
    const G = M(D + B);
    const F = M(G - C2);
    const H = M(D - B);
    const X3 = modP(E * F);
    const Y3 = modP(G * H);
    const T3 = modP(E * H);
    const Z3 = modP(F * G);
    return new Point(X3, Y3, Z3, T3);
  }
  add(other) {
    const { X: X1, Y: Y1, Z: Z1, T: T1 } = this;
    const { X: X2, Y: Y2, Z: Z2, T: T2 } = apoint(other);
    const a = _a;
    const d = _d;
    const A = modP(X1 * X2);
    const B = modP(Y1 * Y2);
    const C2 = modP(modP(T1 * d) * T2);
    const D = modP(Z1 * Z2);
    const E = M(modP(M(X1 + Y1) * M(X2 + Y2)) - A - B);
    const F = M(D - C2);
    const G = M(D + C2);
    const H = M(B - modP(a * A));
    const X3 = modP(E * F);
    const Y3 = modP(G * H);
    const T3 = modP(E * H);
    const Z3 = modP(F * G);
    return new Point(X3, Y3, Z3, T3);
  }
  subtract(other) {
    return this.add(apoint(other).negate());
  }
  multiply(n, safe = true) {
    if (!safe && n === 0n)
      return I;
    assertRange(n, 1n, N);
    if (!safe && this.is0())
      return I;
    if (n === 1n)
      return this;
    if (this.equals(G))
      return wNAF(n).p;
    let p = I;
    let f = G;
    for (let d = this;n > 0n; d = d.double(), n >>= 1n) {
      if (n & 1n)
        p = p.add(d);
      else if (safe)
        f = f.add(d);
    }
    return p;
  }
  multiplyUnsafe(scalar) {
    return this.multiply(scalar, false);
  }
  toAffine() {
    const { X, Y, Z } = this;
    if (this.equals(I))
      return { x: 0n, y: 1n };
    const iz = invert(Z, P);
    if (modP(Z * iz) !== 1n)
      err("invalid inverse");
    const x = modP(X * iz);
    const y = modP(Y * iz);
    return { x, y };
  }
  toBytes() {
    const { x, y } = this.toAffine();
    const b = numTo32bLE(y);
    b[31] |= x & 1n ? 128 : 0;
    return b;
  }
  toHex() {
    return bytesToHex(this.toBytes());
  }
  clearCofactor() {
    return this.multiply(big(h), false);
  }
  isSmallOrder() {
    return this.clearCofactor().is0();
  }
  isTorsionFree() {
    let p = this.multiply(N / 2n, false).double();
    if (N % 2n)
      p = p.add(this);
    return p.is0();
  }
}
var G = new Point(Gx, Gy, 1n, M(Gx * Gy));
var I = new Point(0n, 1n, 1n, 0n);
Point.BASE = G;
Point.ZERO = I;
var numTo32bLE = (num) => hexToBytes(padh(assertRange(num, 0n, B256), 64)).reverse();
var bytesToNumberLE = (b) => big("0x" + bytesToHex(u8fr(abytes(b)).reverse()));
var pow2 = (x, power) => {
  let r = x;
  while (power-- > 0n) {
    r = modP(r * r);
  }
  return r;
};
var pow_2_252_3 = (x) => {
  const x2 = modP(x * x);
  const b2 = modP(x2 * x);
  const b4 = modP(pow2(b2, 2n) * b2);
  const b5 = modP(pow2(b4, 1n) * x);
  const b10 = modP(pow2(b5, 5n) * b5);
  const b20 = modP(pow2(b10, 10n) * b10);
  const b40 = modP(pow2(b20, 20n) * b20);
  const b80 = modP(pow2(b40, 40n) * b40);
  const b160 = modP(pow2(b80, 80n) * b80);
  const b240 = modP(pow2(b160, 80n) * b80);
  const b250 = modP(pow2(b240, 10n) * b10);
  const pow_p_5_8 = modP(pow2(b250, 2n) * x);
  return { pow_p_5_8, b2 };
};
var RM1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0n;
var uvRatio = (u, v) => {
  const v3 = modP(v * modP(v * v));
  const v7 = modP(modP(v3 * v3) * v);
  const pow = pow_2_252_3(modP(u * v7)).pow_p_5_8;
  let x = modP(u * modP(v3 * pow));
  const vx2 = modP(v * modP(x * x));
  const root1 = x;
  const root2 = modP(x * RM1);
  const useRoot1 = vx2 === u;
  const useRoot2 = vx2 === M(-u);
  const noRoot = vx2 === M(-u * RM1);
  if (useRoot1)
    x = root1;
  if (useRoot2 || noRoot)
    x = root2;
  if ((M(x) & 1n) === 1n)
    x = M(-x);
  return { isValid: useRoot1 || useRoot2, value: x };
};
var modL_LE = (hash) => modN(bytesToNumberLE(hash));
var sha512a = (...m) => Promise.resolve(callHash("sha512Async")(concatBytes2(...m))).then(checkDigest);
var hash2extK = (hashed) => {
  const copy = u8fr(hashed);
  const head = copy.slice(0, 32);
  head[0] &= 248;
  head[31] &= 127;
  head[31] |= 64;
  const prefix = copy.slice(32, 64);
  const scalar = modL_LE(head);
  const point = G.multiply(scalar);
  const pointBytes = point.toBytes();
  return { head, prefix, scalar, point, pointBytes };
};
var getExtendedPublicKeyAsync = (secretKey) => sha512a(abytes(secretKey, L)).then(hash2extK);
var getPublicKeyAsync = (secretKey) => getExtendedPublicKeyAsync(secretKey).then((p) => p.pointBytes);
var hashes = {
  sha512Async: async (message2) => {
    const s = subtle();
    const m = concatBytes2(message2);
    return u8n(await s.digest("SHA-512", m.buffer));
  },
  sha512: undefined
};
var W = 8;
var scalarBits = 256;
var pwindows = Math.ceil(scalarBits / W) + 1;
var pwindowSize = 2 ** (W - 1);
var precompute = () => {
  const points = [];
  let p = G;
  let b = p;
  for (let w = 0;w < pwindows; w++) {
    b = p;
    points.push(b);
    for (let i = 1;i < pwindowSize; i++) {
      b = b.add(p);
      points.push(b);
    }
    p = b.double();
  }
  return points;
};
var Gpows = undefined;
var ctneg = (cnd, p) => {
  const n = p.negate();
  return cnd ? n : p;
};
var wNAF = (n) => {
  const comp = Gpows || (Gpows = precompute());
  let p = I;
  let f = G;
  const pow_2_w = 2 ** W;
  const maxNum = pow_2_w;
  const mask = big(pow_2_w - 1);
  const shiftBy = big(W);
  for (let w = 0;w < pwindows; w++) {
    let wbits = Number(n & mask);
    n >>= shiftBy;
    if (wbits > pwindowSize) {
      wbits -= maxNum;
      n += 1n;
    }
    const off = w * pwindowSize;
    const offF = off;
    const offP = off + Math.abs(wbits) - 1;
    const isEven = w % 2 !== 0;
    const isNeg = wbits < 0;
    if (wbits === 0) {
      f = f.add(ctneg(isEven, comp[offF]));
    } else {
      p = p.add(ctneg(isNeg, comp[offP]));
    }
  }
  if (n !== 0n)
    err("invalid wnaf");
  return { p, f };
};

// src/lib/owner-authorization/types.ts
var exports_types = {};
__export(exports_types, {
  SpoolCapabilityAction: () => SpoolCapabilityAction,
  RecoveryGuardianKind: () => RecoveryGuardianKind,
  OwnerKeyTransitionKind: () => OwnerKeyTransitionKind,
  CloneOwnerPinKind: () => CloneOwnerPinKind,
  CapabilityPrincipalKind: () => CapabilityPrincipalKind,
  AuthorizationKeyAlgorithm: () => AuthorizationKeyAlgorithm
});
var AuthorizationKeyAlgorithm;
((AuthorizationKeyAlgorithm2) => {
  AuthorizationKeyAlgorithm2[AuthorizationKeyAlgorithm2["Unspecified"] = 0] = "Unspecified";
  AuthorizationKeyAlgorithm2[AuthorizationKeyAlgorithm2["Ed25519"] = 1] = "Ed25519";
})(AuthorizationKeyAlgorithm ||= {});
var RecoveryGuardianKind;
((RecoveryGuardianKind2) => {
  RecoveryGuardianKind2[RecoveryGuardianKind2["Unspecified"] = 0] = "Unspecified";
  RecoveryGuardianKind2[RecoveryGuardianKind2["Paper"] = 1] = "Paper";
  RecoveryGuardianKind2[RecoveryGuardianKind2["Social"] = 2] = "Social";
  RecoveryGuardianKind2[RecoveryGuardianKind2["Weft"] = 3] = "Weft";
})(RecoveryGuardianKind ||= {});
var OwnerKeyTransitionKind;
((OwnerKeyTransitionKind2) => {
  OwnerKeyTransitionKind2[OwnerKeyTransitionKind2["Unspecified"] = 0] = "Unspecified";
  OwnerKeyTransitionKind2[OwnerKeyTransitionKind2["Rotate"] = 1] = "Rotate";
  OwnerKeyTransitionKind2[OwnerKeyTransitionKind2["Recover"] = 2] = "Recover";
  OwnerKeyTransitionKind2[OwnerKeyTransitionKind2["RecoveryPolicy"] = 3] = "RecoveryPolicy";
  OwnerKeyTransitionKind2[OwnerKeyTransitionKind2["ClaimDeferredHuman"] = 4] = "ClaimDeferredHuman";
})(OwnerKeyTransitionKind ||= {});
var CapabilityPrincipalKind;
((CapabilityPrincipalKind2) => {
  CapabilityPrincipalKind2[CapabilityPrincipalKind2["Unspecified"] = 0] = "Unspecified";
  CapabilityPrincipalKind2[CapabilityPrincipalKind2["HumanDevice"] = 1] = "HumanDevice";
  CapabilityPrincipalKind2[CapabilityPrincipalKind2["ServiceAccount"] = 2] = "ServiceAccount";
  CapabilityPrincipalKind2[CapabilityPrincipalKind2["Agent"] = 3] = "Agent";
  CapabilityPrincipalKind2[CapabilityPrincipalKind2["AnonymousKey"] = 4] = "AnonymousKey";
  CapabilityPrincipalKind2[CapabilityPrincipalKind2["AnyAnonymous"] = 5] = "AnyAnonymous";
})(CapabilityPrincipalKind ||= {});
var SpoolCapabilityAction;
((SpoolCapabilityAction2) => {
  SpoolCapabilityAction2[SpoolCapabilityAction2["Unspecified"] = 0] = "Unspecified";
  SpoolCapabilityAction2[SpoolCapabilityAction2["Read"] = 1] = "Read";
  SpoolCapabilityAction2[SpoolCapabilityAction2["Write"] = 2] = "Write";
  SpoolCapabilityAction2[SpoolCapabilityAction2["Merge"] = 3] = "Merge";
  SpoolCapabilityAction2[SpoolCapabilityAction2["Approve"] = 4] = "Approve";
  SpoolCapabilityAction2[SpoolCapabilityAction2["Admin"] = 5] = "Admin";
  SpoolCapabilityAction2[SpoolCapabilityAction2["Redact"] = 6] = "Redact";
  SpoolCapabilityAction2[SpoolCapabilityAction2["Grant"] = 7] = "Grant";
  SpoolCapabilityAction2[SpoolCapabilityAction2["Purge"] = 8] = "Purge";
})(SpoolCapabilityAction ||= {});
var CloneOwnerPinKind;
((CloneOwnerPinKind2) => {
  CloneOwnerPinKind2[CloneOwnerPinKind2["Unspecified"] = 0] = "Unspecified";
  CloneOwnerPinKind2[CloneOwnerPinKind2["LocalCreation"] = 1] = "LocalCreation";
  CloneOwnerPinKind2[CloneOwnerPinKind2["InvitationFingerprint"] = 2] = "InvitationFingerprint";
})(CloneOwnerPinKind ||= {});

// src/lib/owner-authorization/crypto.ts
var PKCS8_ED25519_PREFIX = Uint8Array.from([
  48,
  46,
  2,
  1,
  0,
  48,
  5,
  6,
  3,
  43,
  101,
  112,
  4,
  34,
  4,
  32
]);
var signingKeys = new WeakMap;
async function generateAuthorizationKey() {
  const pair = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  if (pair.privateKey.extractable) {
    fail("CRYPTO", "authorization private key must be non-extractable");
  }
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return makeHandle(pair.privateKey, publicKey);
}
async function importSeed(seed) {
  assertBytes(seed, 32, "Ed25519 seed");
  const privateKey = await crypto.subtle.importKey("pkcs8", concatBytes(PKCS8_ED25519_PREFIX, seed), "Ed25519", false, ["sign"]);
  const publicKey = new Uint8Array(await getPublicKeyAsync(seed));
  return makeHandle(privateKey, publicKey);
}
function makeHandle(privateKey, publicKey) {
  if (privateKey.type !== "private" || privateKey.algorithm.name !== "Ed25519" || privateKey.extractable || !privateKey.usages.includes("sign")) {
    fail("CRYPTO", "authorization signer is not non-extractable Ed25519");
  }
  assertBytes(publicKey, 32, "Ed25519 public key");
  const handle = Object.freeze({
    verificationKey: Object.freeze({
      algorithm: 1 /* Ed25519 */,
      publicKey: publicKey.slice()
    })
  });
  signingKeys.set(handle, privateKey);
  return handle;
}
async function authorizationKeyId(handle) {
  requirePrivateKey(handle);
  return keyId(handle.verificationKey);
}
async function signCanonical(handle, domain, body) {
  const privateKey = requirePrivateKey(handle);
  const message2 = await digest(domain, body);
  return {
    signerKeyId: await keyId(handle.verificationKey),
    signature: new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, message2))
  };
}
async function signBytes(handle, bytes2) {
  return new Uint8Array(await crypto.subtle.sign("Ed25519", requirePrivateKey(handle), bytes2));
}
async function verifySignature(key, signature, domain, body) {
  if (key.algorithm !== 1 /* Ed25519 */ || key.publicKey.byteLength !== 32 || signature.signerKeyId.byteLength !== 32 || signature.signature.byteLength !== 64 || !bytesEqual(signature.signerKeyId, await keyId(key))) {
    fail("INVALID_SIGNATURE", "owner-authorization signature metadata is invalid");
  }
  const publicKey = await crypto.subtle.importKey("raw", key.publicKey, "Ed25519", false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", publicKey, signature.signature, await digest(domain, body))) {
    fail("INVALID_SIGNATURE", "owner-authorization signature verification failed");
  }
}
function requirePrivateKey(handle) {
  const key = signingKeys.get(handle);
  if (!key) {
    fail("CRYPTO", "authorization key handle is unknown or no longer live");
  }
  if (key.extractable) {
    fail("CRYPTO", "authorization key unexpectedly became extractable");
  }
  return key;
}
async function generatePaperRecoveryKit() {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  try {
    return {
      encodedSeed: base64Url(seed),
      signer: await importSeed(seed)
    };
  } finally {
    seed.fill(0);
  }
}
async function restorePaperRecoveryKit(encodedSeed) {
  const seed = fromBase64Url(encodedSeed);
  assertBytes(seed, 32, "paper recovery seed");
  try {
    return {
      encodedSeed,
      signer: await importSeed(seed)
    };
  } finally {
    seed.fill(0);
  }
}
function randomNonce() {
  return crypto.getRandomValues(new Uint8Array(32));
}
function base64Url(bytes2) {
  let binary = "";
  for (const byte of bytes2)
    binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    fail("INVALID", "paper recovery seed is not unpadded base64url");
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - normalized.length % 4) % 4);
  try {
    return Uint8Array.from(atob(normalized + padding), (char) => char.charCodeAt(0));
  } catch {
    fail("INVALID", "paper recovery seed is not valid base64url");
  }
}
var __ownerAuthorizationCryptoTest = {
  importSeed,
  anonymousCredentialDomain: ANONYMOUS_CREDENTIAL_DOMAIN
};

// src/lib/owner-authorization/root.ts
var exports_root = {};
__export(exports_root, {
  verifyOwnerRoot: () => verifyOwnerRoot,
  verificationKeyEqual: () => verificationKeyEqual,
  recoveryPolicyEqual: () => recoveryPolicyEqual,
  createHumanOwnerRoot: () => createHumanOwnerRoot,
  createDeferredOwnerRoot: () => createDeferredOwnerRoot,
  bytesToHex: () => bytesToHex2,
  VerifiedOwnerState: () => VerifiedOwnerState
});

// src/lib/owner-authorization/recovery.ts
var exports_recovery = {};
__export(exports_recovery, {
  weftGuardian: () => weftGuardian,
  validateWireRecoveryPolicy: () => validateWireRecoveryPolicy,
  toWireRecoveryPolicy: () => toWireRecoveryPolicy,
  socialGuardian: () => socialGuardian,
  recoveryWithThreshold: () => recoveryWithThreshold,
  recommendedRecovery: () => recommendedRecovery,
  paperGuardian: () => paperGuardian,
  custodialWeftOnlyRecovery: () => custodialWeftOnlyRecovery,
  confirmCustodialWeftOnly: () => confirmCustodialWeftOnly
});
function paperGuardian(key) {
  return { kind: 1 /* Paper */, key };
}
function socialGuardian(key) {
  return { kind: 2 /* Social */, key };
}
function weftGuardian(key) {
  return { kind: 3 /* Weft */, key };
}
var confirmedCustody = new WeakSet;
function confirmCustodialWeftOnly() {
  const confirmation = Object.freeze({});
  confirmedCustody.add(confirmation);
  return confirmation;
}
var constructedRecoverySetups = new WeakSet;
async function recommendedRecovery(guardians) {
  return recoveryWithThreshold(2, guardians);
}
async function recoveryWithThreshold(threshold, guardians) {
  if (threshold < 2) {
    fail("INVALID", "recovery threshold below 2 requires the explicit Weft-only confirmation path");
  }
  const setup = Object.freeze({
    threshold,
    guardians: Object.freeze([...guardians])
  });
  await validateSetup(setup, undefined, false);
  constructedRecoverySetups.add(setup);
  return setup;
}
async function custodialWeftOnlyRecovery(guardian, confirmation) {
  if (guardian.kind !== 3 /* Weft */ || !confirmedCustody.has(confirmation)) {
    fail("INVALID", "custodial recovery requires one Weft guardian and explicit confirmation");
  }
  const setup = Object.freeze({
    threshold: 1,
    guardians: Object.freeze([guardian])
  });
  await validateSetup(setup, undefined, true);
  constructedRecoverySetups.add(setup);
  return setup;
}
async function toWireRecoveryPolicy(setup, authority) {
  if (!constructedRecoverySetups.has(setup)) {
    fail("INVALID", "recovery policy was not created through a confirmed construction path");
  }
  const authorityId = await authorizationKeyId(authority);
  await validateSetup(setup, authorityId, setup.threshold === 1);
  const guardians = await Promise.all(setup.guardians.map(async (guardian) => ({
    kind: guardian.kind,
    key: guardian.key.verificationKey,
    id: await authorizationKeyId(guardian.key)
  })));
  guardians.sort((left, right) => compareBytes(left.id, right.id));
  return {
    threshold: setup.threshold,
    guardians: guardians.map(({ kind, key }) => ({ kind, key }))
  };
}
async function validateSetup(setup, authorityId, allowCustodial) {
  if (!Number.isInteger(setup.threshold) || setup.threshold <= 0 || setup.threshold > setup.guardians.length) {
    fail("INVALID", "recovery threshold exceeds the guardian set");
  }
  if (setup.threshold < 2 && (!allowCustodial || setup.guardians.length !== 1 || setup.guardians[0].kind !== 3 /* Weft */)) {
    fail("INVALID", "1-of-1 recovery is allowed only for explicitly confirmed Weft custody");
  }
  const hasWeft = setup.guardians.some(({ kind }) => kind === 3 /* Weft */);
  const hasIndependent = setup.guardians.some(({ kind }) => [1 /* Paper */, 2 /* Social */].includes(kind));
  if (hasWeft && setup.threshold >= 2 && !hasIndependent) {
    fail("INVALID", "a Weft guardian requires a paper or social co-factor");
  }
  const ids = [];
  for (const guardian of setup.guardians) {
    const id = await authorizationKeyId(guardian.key);
    if (authorityId !== undefined && bytesEqual(authorityId, id) || ids.some((prior) => bytesEqual(prior, id))) {
      fail("INVALID", "authority and recovery guardian keys must be distinct");
    }
    ids.push(id);
  }
}
async function validateWireRecoveryPolicy(policy, authorityKeyId, allowEmpty) {
  if (allowEmpty && policy.threshold === 0 && policy.guardians.length === 0) {
    return;
  }
  if (!Number.isInteger(policy.threshold) || policy.threshold <= 0 || policy.threshold > policy.guardians.length) {
    fail("INVALID", "recovery threshold is outside the guardian set");
  }
  const custodial = policy.threshold === 1 && policy.guardians.length === 1 && policy.guardians[0].kind === 3 /* Weft */;
  if (policy.threshold < 2 && !custodial) {
    fail("INVALID", "wire policy has an unapproved threshold below 2");
  }
  const hasWeft = policy.guardians.some(({ kind }) => kind === 3 /* Weft */);
  const hasIndependent = policy.guardians.some(({ kind }) => [1 /* Paper */, 2 /* Social */].includes(kind));
  if (hasWeft && !custodial && !hasIndependent) {
    fail("INVALID", "Weft recovery lacks a paper or social co-factor");
  }
  const ids = [];
  for (const guardian of policy.guardians) {
    if (![
      1 /* Paper */,
      2 /* Social */,
      3 /* Weft */
    ].includes(guardian.kind)) {
      fail("INVALID", "unknown recovery guardian kind");
    }
    const key = requireValue(guardian.key, "RecoveryGuardian.key");
    if (key.algorithm !== 1 /* Ed25519 */ || key.publicKey.byteLength !== 32) {
      fail("INVALID", "recovery guardian key is not 32-byte Ed25519");
    }
    const id = await keyId(key);
    if (bytesEqual(id, authorityKeyId)) {
      fail("INVALID", "authority key cannot also be a recovery guardian");
    }
    ids.push(id);
  }
  for (let index = 1;index < ids.length; index++) {
    if (compareBytes(ids[index - 1], ids[index]) >= 0) {
      fail("INVALID", "recovery guardians must be unique and sorted by key id");
    }
  }
}

// src/lib/owner-authorization/root.ts
class VerifiedOwnerState {
  signedRoot;
  ownerId;
  stateHash;
  sequence;
  authorityKey;
  recoveryPolicy;
  claimableDeferredHuman;
  claimableUntilUnixSeconds;
  #issuers;
  constructor(signedRoot, ownerId, stateHash, sequence, authorityKey, recoveryPolicy2, claimableDeferredHuman, claimableUntilUnixSeconds, issuers) {
    this.signedRoot = signedRoot;
    this.ownerId = ownerId;
    this.stateHash = stateHash;
    this.sequence = sequence;
    this.authorityKey = authorityKey;
    this.recoveryPolicy = recoveryPolicy2;
    this.claimableDeferredHuman = claimableDeferredHuman;
    this.claimableUntilUnixSeconds = claimableUntilUnixSeconds;
    this.#issuers = issuers;
  }
  issuerAt(stateHash, nowUnixSeconds) {
    assertBytes(stateHash, 32, "issuer state hash");
    const issuer = this.#issuers.get(bytesToHex2(stateHash));
    if (!issuer)
      fail("BROKEN_CHAIN", "unknown capability issuer state");
    if (issuer.validUntil !== undefined && (issuer.validUntil === 0n || nowUnixSeconds > issuer.validUntil)) {
      fail("EXPIRED", "capability issuer key is retired");
    }
    if (this.claimableDeferredHuman && this.claimableUntilUnixSeconds > 0n && nowUnixSeconds > this.claimableUntilUnixSeconds) {
      fail("EXPIRED", "deferred owner root is no longer claimable");
    }
    return issuer.key;
  }
  withTransition(stateHash, sequence, authorityKey, recoveryPolicy2, priorValidUntil, claimed) {
    const issuers = new Map([...this.#issuers].map(([hash, issuer]) => [hash, { ...issuer }]));
    const prior = issuers.get(bytesToHex2(this.stateHash));
    if (!prior)
      fail("BROKEN_CHAIN", "verified current issuer is absent");
    prior.validUntil = priorValidUntil;
    issuers.set(bytesToHex2(stateHash), { key: authorityKey });
    return new VerifiedOwnerState(this.signedRoot, this.ownerId, stateHash, sequence, authorityKey, recoveryPolicy2, claimed ? false : this.claimableDeferredHuman, this.claimableUntilUnixSeconds, issuers);
  }
}
async function createHumanOwnerRoot(accountUuid, authority, recovery) {
  return createOwnerRoot(accountUuid, authority, recovery, false, 0n);
}
async function createDeferredOwnerRoot(accountUuid, origin, claimableUntilUnixSeconds) {
  if (claimableUntilUnixSeconds <= 0n) {
    fail("INVALID", "deferred owner root requires a positive claim deadline");
  }
  return createOwnerRoot(accountUuid, origin, undefined, true, claimableUntilUnixSeconds);
}
async function createOwnerRoot(accountUuid, authority, recovery, claimableDeferredHuman, claimableUntilUnixSeconds) {
  assertBytes(accountUuid, 16, "account UUID");
  const recoveryPolicy2 = recovery === undefined ? { threshold: 0, guardians: [] } : await toWireRecoveryPolicy(recovery, authority);
  const root = {
    formatVersion: 1,
    ownerId: new Uint8Array,
    accountUuid: accountUuid.slice(),
    authorityKey: authority.verificationKey,
    recoveryPolicy: recoveryPolicy2,
    claimableDeferredHuman,
    nonce: randomNonce(),
    claimableUntilUnixSeconds
  };
  root.ownerId = await digest(OWNER_ROOT_DOMAIN, await ownerRootWithoutId(root));
  const body = await ownerRootBody(root);
  const recoveryKeyProofs = recovery === undefined ? [] : await Promise.all(recovery.guardians.map(({ key }) => signCanonical(key, OWNER_ROOT_DOMAIN, body)));
  recoveryKeyProofs.sort((left, right) => compareSignatureIds(left.signerKeyId, right.signerKeyId));
  return {
    root,
    authorityProof: await signCanonical(authority, OWNER_ROOT_DOMAIN, body),
    recoveryKeyProofs
  };
}
async function verifyOwnerRoot(signed) {
  const root = requireValue(signed.root, "SignedOwnerRoot.root");
  if (root.formatVersion !== 1 || root.ownerId.byteLength !== 32 || root.accountUuid.byteLength !== 16 || root.nonce.byteLength !== 32) {
    fail("INVALID", "owner root has invalid v1 field lengths");
  }
  const authority = requireValue(root.authorityKey, "OwnerRoot.authorityKey");
  if (authority.algorithm !== 1 /* Ed25519 */ || authority.publicKey.byteLength !== 32) {
    fail("INVALID", "owner authority is not 32-byte Ed25519");
  }
  if (root.claimableDeferredHuman !== root.claimableUntilUnixSeconds > 0n) {
    fail("INVALID", "deferred claim flag and deadline disagree");
  }
  const expectedOwnerId = await digest(OWNER_ROOT_DOMAIN, await ownerRootWithoutId(root));
  if (!bytesEqual(root.ownerId, expectedOwnerId)) {
    fail("INVALID", "owner id does not match the canonical root");
  }
  const policy = requireValue(root.recoveryPolicy, "OwnerRoot.recoveryPolicy");
  await validateWireRecoveryPolicy(policy, await keyId(authority), root.claimableDeferredHuman);
  const body = await ownerRootBody(root);
  await verifySignature(authority, requireValue(signed.authorityProof, "SignedOwnerRoot.authorityProof"), OWNER_ROOT_DOMAIN, body);
  if (signed.recoveryKeyProofs.length !== policy.guardians.length) {
    fail("INVALID", "owner root recovery proof count does not match guardians");
  }
  for (let index = 0;index < policy.guardians.length; index++) {
    await verifySignature(requireValue(policy.guardians[index].key, "RecoveryGuardian.key"), signed.recoveryKeyProofs[index], OWNER_ROOT_DOMAIN, body);
  }
  const stateHash = await digest(OWNER_ROOT_DOMAIN, body);
  return new VerifiedOwnerState(signed, expectedOwnerId, stateHash, 0n, authority, policy, root.claimableDeferredHuman, root.claimableUntilUnixSeconds, new Map([[bytesToHex2(stateHash), { key: authority }]]));
}
function verificationKeyEqual(left, right) {
  return left.algorithm === right.algorithm && bytesEqual(left.publicKey, right.publicKey);
}
function recoveryPolicyEqual(left, right) {
  return left.threshold === right.threshold && left.guardians.length === right.guardians.length && left.guardians.every((guardian, index) => {
    const other = right.guardians[index];
    return guardian.kind === other.kind && guardian.key !== undefined && other.key !== undefined && verificationKeyEqual(guardian.key, other.key);
  });
}
function bytesToHex2(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function compareSignatureIds(left, right) {
  const length = Math.min(left.byteLength, right.byteLength);
  for (let index = 0;index < length; index++) {
    if (left[index] !== right[index])
      return left[index] - right[index];
  }
  return left.byteLength - right.byteLength;
}

// src/lib/owner-authorization/subject-biscuit.ts
var BLOCK_VERSION = 3;
var SIGNATURE_VERSION = 0;
var ED25519_ALGORITHM = 0;
var SYMBOL_OFFSET = 1024;

class Symbols {
  values = [];
  #ids = new Map;
  intern(value) {
    const existing = this.#ids.get(value);
    if (existing !== undefined)
      return existing;
    const id = SYMBOL_OFFSET + this.values.length;
    this.values.push(value);
    this.#ids.set(value, id);
    return id;
  }
}
function pathHex(segments) {
  const parts = [];
  for (const segment of segments) {
    const value = new TextEncoder().encode(segment);
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, value.byteLength, false);
    parts.push(length, value);
  }
  return bytesToHex2(concatBytes(...parts));
}
function expectedFacts(capability) {
  const subject = requireValue(capability.subject, "OwnerCapability.subject");
  const key = requireValue(subject.key, "CapabilityPrincipal.key");
  const facts = [
    {
      predicate: "owner_subject",
      terms: [
        { kind: "integer", value: BigInt(subject.kind) },
        { kind: "string", value: bytesToHex2(subject.principalId) },
        { kind: "string", value: bytesToHex2(key.publicKey) }
      ]
    },
    {
      predicate: "owner_capability",
      terms: [{ kind: "string", value: bytesToHex2(capability.capabilityId) }]
    },
    {
      predicate: "owner_validity",
      terms: [
        { kind: "integer", value: capability.notBeforeUnixSeconds },
        { kind: "integer", value: capability.expiresAtUnixSeconds }
      ]
    }
  ];
  const grants = [];
  for (const grant2 of capability.grants) {
    const selector2 = requireValue(grant2.spool, "SpoolCapabilityGrant.spool");
    for (const action of grant2.actions) {
      grants.push([
        bytesToHex2(selector2.rootSpoolUuid),
        pathHex(selector2.pathSegments),
        selector2.includeDescendants,
        action
      ]);
    }
  }
  grants.sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
  for (const [spool, path, descendants, action] of grants) {
    facts.push({
      predicate: "owner_grant",
      terms: [
        { kind: "string", value: spool },
        { kind: "string", value: path },
        { kind: "boolean", value: descendants },
        { kind: "integer", value: BigInt(action) }
      ]
    });
  }
  return facts;
}
async function expectedFactKeys(capability) {
  const facts = expectedFacts(capability);
  const subject = requireValue(capability.subject, "OwnerCapability.subject");
  const subjectKey = requireValue(subject.key, "CapabilityPrincipal.key");
  const ownerSubject = facts[0];
  ownerSubject.terms[2] = {
    kind: "string",
    value: bytesToHex2(await keyId(subjectKey))
  };
  return facts.map(factKey).sort();
}
function encodeBlock(facts) {
  const symbols = new Symbols;
  const encoded = facts.map((fact) => encodeFact(fact, symbols));
  const writer = new ProtoWriter;
  for (const symbol of symbols.values)
    writer.string(1, symbol, true);
  writer.varint(3, BigInt(BLOCK_VERSION));
  for (const fact of encoded)
    writer.bytes(4, fact, true);
  return writer.finish();
}
function encodeFact(fact, symbols) {
  const predicate = new ProtoWriter;
  predicate.varint(1, BigInt(symbols.intern(fact.predicate)));
  for (const term of fact.terms) {
    const encoded = new ProtoWriter;
    if (term.kind === "string") {
      encoded.varint(3, BigInt(symbols.intern(term.value)));
    } else if (term.kind === "integer") {
      encoded.varint(2, BigInt.asUintN(64, term.value));
    } else {
      encoded.varint(6, term.value ? 1n : 0n);
    }
    predicate.bytes(2, encoded.finish(), true);
  }
  const factWriter = new ProtoWriter;
  factWriter.bytes(1, predicate.finish(), true);
  return factWriter.finish();
}
async function generateProofKey() {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  return {
    seed,
    publicKey: new Uint8Array(await getPublicKeyAsync(seed))
  };
}
function signaturePayload(block, nextPublicKey) {
  return concatBytes(block, Uint8Array.of(0, 0, 0, 0), nextPublicKey);
}
async function mintSubjectBiscuit(capability, subjectKey) {
  const subject = requireValue(capability.subject, "OwnerCapability.subject");
  const publicKey = requireValue(subject.key, "CapabilityPrincipal.key");
  if (!bytesEqual(await authorizationKeyId(subjectKey), await keyId(publicKey))) {
    fail("INVALID", "Biscuit signer does not match the capability subject");
  }
  const block = encodeBlock(await factsForEncoding(capability));
  const proof = await generateProofKey();
  try {
    const authority = {
      block,
      nextPublicKey: proof.publicKey,
      signature: await signBytes(subjectKey, signaturePayload(block, proof.publicKey)),
      version: SIGNATURE_VERSION
    };
    return encodeBiscuit({
      authority,
      blocks: [],
      proofSecret: proof.seed
    });
  } finally {
    proof.seed.fill(0);
  }
}
async function factsForEncoding(capability) {
  const facts = expectedFacts(capability);
  const subject = requireValue(capability.subject, "OwnerCapability.subject");
  facts[0].terms[2] = {
    kind: "string",
    value: bytesToHex2(await keyId(requireValue(subject.key, "CapabilityPrincipal.key")))
  };
  return facts;
}
async function verifySubjectBiscuit(capability, bytes2) {
  const subject = requireValue(capability.subject, "OwnerCapability.subject");
  if (subject.kind === 5 /* AnyAnonymous */) {
    if (bytes2.byteLength === 0)
      return;
    fail("INVALID", "ANY_ANONYMOUS bundle must not claim a subject-signed Biscuit");
  }
  const key = requireValue(subject.key, "CapabilityPrincipal.key");
  const biscuit = decodeBiscuit(bytes2);
  if (biscuit.blocks.length !== 0) {
    fail("CAPABILITY_DENIED", "subject Biscuit must contain only its authority block");
  }
  await verifySignedBlock(biscuit.authority, key.publicKey);
  if (!bytesEqual(new Uint8Array(await getPublicKeyAsync(biscuit.proofSecret)), biscuit.authority.nextPublicKey)) {
    fail("INVALID_SIGNATURE", "Biscuit proof secret does not match terminal key");
  }
  const actual = decodeFacts(biscuit.authority.block).map(factKey).sort();
  const expected = await expectedFactKeys(capability);
  if (actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) {
    fail("CAPABILITY_DENIED", "subject Biscuit facts differ from the leaf capability");
  }
}
async function verifySignedBlock(signed, publicKeyBytes) {
  if (signed.version !== SIGNATURE_VERSION || signed.nextPublicKey.byteLength !== 32 || signed.signature.byteLength !== 64) {
    fail("INVALID_SIGNATURE", "Biscuit signed block metadata is invalid");
  }
  const publicKey = await crypto.subtle.importKey("raw", publicKeyBytes, "Ed25519", false, ["verify"]);
  if (!await crypto.subtle.verify("Ed25519", publicKey, signed.signature, signaturePayload(signed.block, signed.nextPublicKey))) {
    fail("INVALID_SIGNATURE", "subject Biscuit signature is invalid");
  }
}
function encodeBiscuit(value) {
  const writer = new ProtoWriter;
  writer.bytes(2, encodeSignedBlock(value.authority), true);
  for (const block of value.blocks) {
    writer.bytes(3, encodeSignedBlock(block), true);
  }
  const proof = new ProtoWriter;
  proof.bytes(1, value.proofSecret, true);
  writer.bytes(4, proof.finish(), true);
  return writer.finish();
}
function encodeSignedBlock(value) {
  const writer = new ProtoWriter;
  writer.bytes(1, value.block, true);
  const key = new ProtoWriter;
  key.varint(1, BigInt(ED25519_ALGORITHM));
  key.bytes(2, value.nextPublicKey, true);
  writer.bytes(2, key.finish(), true);
  writer.bytes(3, value.signature, true);
  if (value.version !== SIGNATURE_VERSION) {
    writer.varint(5, BigInt(value.version));
  }
  return writer.finish();
}
function decodeBiscuit(bytes2) {
  const reader = new ProtoReader(bytes2);
  let authority;
  const blocks = [];
  let proofSecret;
  while (!reader.done) {
    const { field, wire } = reader.tag();
    if (field === 2 && wire === 2)
      authority = decodeSignedBlock(reader.bytes());
    else if (field === 3 && wire === 2)
      blocks.push(decodeSignedBlock(reader.bytes()));
    else if (field === 4 && wire === 2)
      proofSecret = decodeProof(reader.bytes());
    else
      reader.skip(wire);
  }
  if (!authority || !proofSecret || proofSecret.byteLength !== 32) {
    fail("INVALID", "invalid subject Biscuit container");
  }
  return { authority, blocks, proofSecret };
}
function decodeSignedBlock(bytes2) {
  const reader = new ProtoReader(bytes2);
  let block;
  let nextPublicKey;
  let signature;
  let version = SIGNATURE_VERSION;
  while (!reader.done) {
    const { field, wire } = reader.tag();
    if (field === 1 && wire === 2)
      block = reader.bytes();
    else if (field === 2 && wire === 2) {
      nextPublicKey = decodePublicKey(reader.bytes());
    } else if (field === 3 && wire === 2)
      signature = reader.bytes();
    else if (field === 4)
      fail("INVALID", "third-party Biscuit block is unsupported");
    else if (field === 5 && wire === 0)
      version = reader.number();
    else
      reader.skip(wire);
  }
  if (!block || !nextPublicKey || !signature) {
    fail("INVALID", "invalid subject Biscuit SignedBlock");
  }
  return { block, nextPublicKey, signature, version };
}
function decodePublicKey(bytes2) {
  const reader = new ProtoReader(bytes2);
  let algorithm;
  let key;
  while (!reader.done) {
    const { field, wire } = reader.tag();
    if (field === 1 && wire === 0)
      algorithm = reader.number();
    else if (field === 2 && wire === 2)
      key = reader.bytes();
    else
      reader.skip(wire);
  }
  if (algorithm !== ED25519_ALGORITHM || !key || key.byteLength !== 32) {
    fail("INVALID", "subject Biscuit public key is invalid");
  }
  return key;
}
function decodeProof(bytes2) {
  const reader = new ProtoReader(bytes2);
  let secret;
  while (!reader.done) {
    const { field, wire } = reader.tag();
    if (field === 1 && wire === 2)
      secret = reader.bytes();
    else if (field === 2)
      fail("INVALID", "sealed subject Biscuit is unsupported");
    else
      reader.skip(wire);
  }
  if (!secret)
    fail("INVALID", "subject Biscuit proof is missing");
  return secret;
}
function decodeFacts(block) {
  const reader = new ProtoReader(block);
  const symbols = [];
  const encodedFacts = [];
  let version = 0;
  while (!reader.done) {
    const { field, wire } = reader.tag();
    if (field === 1 && wire === 2)
      symbols.push(reader.string());
    else if (field === 3 && wire === 0)
      version = reader.number();
    else if (field === 4 && wire === 2)
      encodedFacts.push(reader.bytes());
    else if (field === 6) {
      fail("CAPABILITY_DENIED", "subject Biscuit may not add authority checks");
    } else
      reader.skip(wire);
  }
  if (version !== BLOCK_VERSION) {
    fail("INVALID", "unsupported subject Biscuit block version");
  }
  return encodedFacts.map((fact) => decodeFact(fact, symbols));
}
function decodeFact(bytes2, symbols) {
  const reader = new ProtoReader(bytes2);
  let predicateBytes;
  while (!reader.done) {
    const { field, wire } = reader.tag();
    if (field === 1 && wire === 2)
      predicateBytes = reader.bytes();
    else
      reader.skip(wire);
  }
  if (!predicateBytes)
    fail("INVALID", "subject Biscuit fact has no predicate");
  const predicate = new ProtoReader(predicateBytes);
  let name;
  const terms = [];
  while (!predicate.done) {
    const { field, wire } = predicate.tag();
    if (field === 1 && wire === 0) {
      name = resolveSymbol(predicate.number(), symbols);
    } else if (field === 2 && wire === 2) {
      terms.push(decodeTerm(predicate.bytes(), symbols));
    } else
      predicate.skip(wire);
  }
  if (!name)
    fail("INVALID", "subject Biscuit fact has no name");
  return { predicate: name, terms };
}
function decodeTerm(bytes2, symbols) {
  const reader = new ProtoReader(bytes2);
  let term;
  while (!reader.done) {
    const { field, wire } = reader.tag();
    if (field === 2 && wire === 0) {
      term = { kind: "integer", value: BigInt.asIntN(64, reader.varint()) };
    } else if (field === 3 && wire === 0) {
      term = { kind: "string", value: resolveSymbol(reader.number(), symbols) };
    } else if (field === 6 && wire === 0) {
      term = { kind: "boolean", value: reader.number() !== 0 };
    } else {
      fail("CAPABILITY_DENIED", "subject Biscuit fact has an unsupported term");
    }
  }
  if (!term)
    fail("INVALID", "subject Biscuit fact term is missing");
  return term;
}
function resolveSymbol(id, symbols) {
  const index = id - SYMBOL_OFFSET;
  if (index < 0 || index >= symbols.length) {
    fail("CAPABILITY_DENIED", "subject Biscuit references an unexpected symbol");
  }
  return symbols[index];
}
function factKey(fact) {
  return JSON.stringify({
    predicate: fact.predicate,
    terms: fact.terms.map((term) => ({
      kind: term.kind,
      value: term.value.toString()
    }))
  });
}

// src/lib/owner-authorization/transition.ts
function validateOverlap(validFrom, previousValidUntil, limits) {
  if (validFrom < 0n || previousValidUntil < 0n || previousValidUntil > 0n && previousValidUntil < validFrom || previousValidUntil - validFrom > limits.maxCapabilityTtlSeconds) {
    fail("INVALID", "previous-key handover exceeds the capability TTL ceiling");
  }
}
async function verifyThreshold(policy, signatures, body) {
  const guardians = new Map;
  for (const guardian of policy.guardians) {
    const key = requireValue(guardian.key, "RecoveryGuardian.key");
    guardians.set(bytesToHex3(await keyId(key)), key);
  }
  const seen = new Set;
  for (const signature of signatures) {
    const id = bytesToHex3(signature.signerKeyId);
    const key = guardians.get(id);
    if (!key || seen.has(id)) {
      fail("INVALID_SIGNATURE", "recovery signature is unknown or duplicated");
    }
    seen.add(id);
    await verifySignature(key, signature, OWNER_TRANSITION_DOMAIN, body);
  }
  if (seen.size < policy.threshold) {
    fail("RECOVERY_THRESHOLD", "recovery threshold is not satisfied", {
      required: policy.threshold,
      actual: seen.size
    });
  }
}
async function verifyExactSignature(signatures, key, body) {
  const expected = await keyId(key);
  const matching = signatures.filter(({ signerKeyId }) => bytesEqual(signerKeyId, expected));
  if (matching.length !== 1) {
    fail("INVALID_SIGNATURE", "required authority signature is absent or duplicated");
  }
  await verifySignature(key, matching[0], OWNER_TRANSITION_DOMAIN, body);
  return signatures.filter(({ signerKeyId }) => !bytesEqual(signerKeyId, expected));
}
async function verifyNextGuardians(policy, proofs, body) {
  if (proofs.length !== policy.guardians.length) {
    fail("INVALID", "next recovery proof count does not match policy");
  }
  for (let index = 0;index < policy.guardians.length; index++) {
    await verifySignature(requireValue(policy.guardians[index].key, "RecoveryGuardian.key"), proofs[index], OWNER_TRANSITION_DOMAIN, body);
  }
}
async function applyTransition(state, signed, nowUnixSeconds, limits) {
  const transition = requireValue(signed.transition, "SignedOwnerKeyTransition.transition");
  if (transition.formatVersion !== 1 || !bytesEqual(transition.ownerId, state.ownerId) || !bytesEqual(transition.previousStateHash, state.stateHash) || transition.sequence !== state.sequence + 1n || transition.nonce.byteLength !== 32) {
    fail("BROKEN_CHAIN", "owner id, previous state hash, or sequence does not match");
  }
  validateOverlap(transition.validFromUnixSeconds, transition.previousKeyValidUntilUnixSeconds, limits);
  if (nowUnixSeconds < transition.validFromUnixSeconds) {
    fail("NOT_YET_VALID", "owner transition is not valid yet");
  }
  if (![
    1 /* Rotate */,
    2 /* Recover */,
    3 /* RecoveryPolicy */,
    4 /* ClaimDeferredHuman */
  ].includes(transition.kind)) {
    fail("INVALID", "unknown transition kind");
  }
  const nextAuthority = requireValue(transition.nextAuthorityKey, "OwnerKeyTransition.nextAuthorityKey");
  const nextPolicy = requireValue(transition.nextRecoveryPolicy, "OwnerKeyTransition.nextRecoveryPolicy");
  await validateWireRecoveryPolicy(nextPolicy, await keyId(nextAuthority), false);
  const body = await transitionBody(transition);
  if (transition.kind === 1 /* Rotate */) {
    if (!recoveryPolicyEqual(nextPolicy, state.recoveryPolicy) || signed.authorizations.length !== 1 || signed.nextRecoveryKeyProofs.length !== 0) {
      fail("INVALID", "rotation changed recovery policy or has extra proofs");
    }
    await verifySignature(state.authorityKey, signed.authorizations[0], OWNER_TRANSITION_DOMAIN, body);
    await verifySignature(nextAuthority, requireValue(signed.nextAuthorityKeyProof, "SignedOwnerKeyTransition.nextAuthorityKeyProof"), OWNER_TRANSITION_DOMAIN, body);
  } else if (transition.kind === 2 /* Recover */) {
    if (!recoveryPolicyEqual(nextPolicy, state.recoveryPolicy) || transition.previousKeyValidUntilUnixSeconds !== 0n || signed.nextRecoveryKeyProofs.length !== 0) {
      fail("INVALID", "recovery changed policy or retained compromised authority");
    }
    await verifyThreshold(state.recoveryPolicy, signed.authorizations, body);
    await verifySignature(nextAuthority, requireValue(signed.nextAuthorityKeyProof, "SignedOwnerKeyTransition.nextAuthorityKeyProof"), OWNER_TRANSITION_DOMAIN, body);
  } else if (transition.kind === 3 /* RecoveryPolicy */) {
    if (!verificationKeyEqual(nextAuthority, state.authorityKey) || signed.nextAuthorityKeyProof !== undefined) {
      fail("INVALID", "recovery-policy transition changed authority");
    }
    const guardianSignatures = await verifyExactSignature(signed.authorizations, state.authorityKey, body);
    await verifyThreshold(state.recoveryPolicy, guardianSignatures, body);
    await verifyNextGuardians(nextPolicy, signed.nextRecoveryKeyProofs, body);
  } else {
    if (!state.claimableDeferredHuman || nowUnixSeconds > state.claimableUntilUnixSeconds || transition.validFromUnixSeconds > state.claimableUntilUnixSeconds || signed.authorizations.length !== 1) {
      fail("INVALID", "claim transition does not originate from a claimable state");
    }
    await verifySignature(state.authorityKey, signed.authorizations[0], OWNER_TRANSITION_DOMAIN, body);
    await verifySignature(nextAuthority, requireValue(signed.nextAuthorityKeyProof, "SignedOwnerKeyTransition.nextAuthorityKeyProof"), OWNER_TRANSITION_DOMAIN, body);
    await verifyNextGuardians(nextPolicy, signed.nextRecoveryKeyProofs, body);
  }
  return state.withTransition(await digest(OWNER_TRANSITION_DOMAIN, body), transition.sequence, nextAuthority, nextPolicy, transition.previousKeyValidUntilUnixSeconds, transition.kind === 4 /* ClaimDeferredHuman */);
}
function bytesToHex3(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

// src/lib/owner-authorization/capability.ts
class VerifiedCapability {
  signed;
  constructor(signed) {
    this.signed = signed;
  }
  get capability() {
    return requireValue(this.signed.capability, "SignedOwnerCapability.capability");
  }
  get ownerId() {
    return this.capability.ownerId;
  }
  get issuerStateHash() {
    return this.capability.issuerStateHash;
  }
}

class VerifiedAuthorizationBundle {
  ownerState;
  leaf;
  constructor(ownerState, leaf) {
    this.ownerState = ownerState;
    this.leaf = leaf;
  }
}
function validatePathSegments(segments) {
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === ".." || segment.includes("/") || segment.includes("\x00"))) {
    fail("INVALID", "spool path contains a non-canonical segment");
  }
}
function validateSelector(selector2) {
  assertBytes(selector2.rootSpoolUuid, 16, "spool selector UUID");
  validatePathSegments(selector2.pathSegments);
}
function validateGrant(grant2) {
  const selector2 = requireValue(grant2.spool, "SpoolCapabilityGrant.spool");
  validateSelector(selector2);
  if (grant2.actions.length === 0) {
    fail("INVALID", "capability grant has no actions");
  }
  let previous = 0;
  for (const action of grant2.actions) {
    if (![
      1 /* Read */,
      2 /* Write */,
      3 /* Merge */,
      4 /* Approve */,
      5 /* Admin */,
      6 /* Redact */,
      7 /* Grant */,
      8 /* Purge */
    ].includes(action)) {
      fail("INVALID", "unknown capability action");
    }
    if (previous >= action) {
      fail("INVALID", "capability actions must be unique and sorted");
    }
    if (action === 8 /* Purge */ && selector2.includeDescendants) {
      fail("INVALID", "purge requires an exact spool selector");
    }
    previous = action;
  }
}
function validateCapability(capability, limits) {
  if (capability.formatVersion !== 1 || capability.ownerId.byteLength !== 32 || capability.issuerStateHash.byteLength !== 32 || capability.nonce.byteLength !== 32 || capability.capabilityId.byteLength !== 32 || capability.notBeforeUnixSeconds < 0n || capability.expiresAtUnixSeconds <= capability.notBeforeUnixSeconds || capability.expiresAtUnixSeconds - capability.notBeforeUnixSeconds > limits.maxCapabilityTtlSeconds || capability.grants.length === 0) {
    fail("INVALID", "owner capability has invalid v1 fields or lifetime");
  }
  const subject = requireValue(capability.subject, "OwnerCapability.subject");
  if (![
    1 /* HumanDevice */,
    2 /* ServiceAccount */,
    3 /* Agent */,
    4 /* AnonymousKey */,
    5 /* AnyAnonymous */
  ].includes(subject.kind)) {
    fail("INVALID", "unknown capability principal");
  }
  if (subject.kind === 5 /* AnyAnonymous */) {
    if (subject.key !== undefined || subject.principalId.byteLength !== 0) {
      fail("INVALID", "ANY_ANONYMOUS must omit key and principal id");
    }
  } else if (subject.principalId.byteLength === 0 || subject.key === undefined || subject.key.algorithm !== 1 /* Ed25519 */ || subject.key.publicKey.byteLength !== 32) {
    fail("INVALID", "capability subject key or principal id is invalid");
  }
  for (const grant2 of capability.grants)
    validateGrant(grant2);
}
function selectorCovers(parent, child) {
  if (!bytesEqual(parent.rootSpoolUuid, child.rootSpoolUuid))
    return false;
  if (parent.includeDescendants) {
    return pathStartsWith(child.pathSegments, parent.pathSegments);
  }
  return pathsEqual(parent.pathSegments, child.pathSegments) && !child.includeDescendants;
}
function grantCovers(parent, child) {
  return child.every((childGrant) => {
    const childSpool = childGrant.spool;
    if (!childSpool)
      return false;
    return parent.some((parentGrant) => {
      const parentSpool = parentGrant.spool;
      if (!parentSpool)
        return false;
      const actions = new Set(parentGrant.actions);
      return actions.has(7 /* Grant */) && childGrant.actions.every((action) => actions.has(action)) && selectorCovers(parentSpool, childSpool);
    });
  });
}
function requestMatchesSelector(granted, requestedSpoolUuid, requestedPath) {
  if (!bytesEqual(granted.rootSpoolUuid, requestedSpoolUuid))
    return false;
  return granted.includeDescendants ? pathStartsWith(requestedPath, granted.pathSegments) : pathsEqual(requestedPath, granted.pathSegments);
}
async function unsignedCapability(ownerId, issuerStateHash, parentCapabilityId, subject, grants, notBeforeUnixSeconds, expiresAtUnixSeconds, limits) {
  const capability = {
    formatVersion: 1,
    ownerId: ownerId.slice(),
    issuerStateHash: issuerStateHash.slice(),
    parentCapabilityId: parentCapabilityId.slice(),
    subject,
    grants,
    notBeforeUnixSeconds,
    expiresAtUnixSeconds,
    nonce: randomNonce(),
    capabilityId: new Uint8Array(32)
  };
  validateCapability(capability, limits);
  capability.capabilityId = await digest(OWNER_CAPABILITY_DOMAIN, await capabilityWithoutId(capability));
  return capability;
}
async function createDirectCapability(state, authority, subject, grants, notBeforeUnixSeconds, expiresAtUnixSeconds, limits) {
  if (!bytesEqual(await authorizationKeyId(authority), await keyId(state.authorityKey))) {
    fail("INVALID", "direct capability signer is not the active owner authority");
  }
  const capability = await unsignedCapability(state.ownerId, state.stateHash, new Uint8Array, subject, grants, notBeforeUnixSeconds, expiresAtUnixSeconds, limits);
  return {
    capability,
    signature: await signCanonical(authority, OWNER_CAPABILITY_DOMAIN, await capabilityBody(capability))
  };
}
async function createChildCapability(parent, parentSubjectKey, subject, grants, notBeforeUnixSeconds, expiresAtUnixSeconds, limits) {
  const parentBody = parent.capability;
  const parentKey = requireValue(requireValue(parentBody.subject, "OwnerCapability.subject").key, "CapabilityPrincipal.key");
  if (!bytesEqual(await authorizationKeyId(parentSubjectKey), await keyId(parentKey)) || notBeforeUnixSeconds < parentBody.notBeforeUnixSeconds || expiresAtUnixSeconds > parentBody.expiresAtUnixSeconds || !grantCovers(parentBody.grants, grants)) {
    fail("CAPABILITY_DENIED", "child capability widens its parent");
  }
  const capability = await unsignedCapability(parent.ownerId, parent.issuerStateHash, parentBody.capabilityId, subject, grants, notBeforeUnixSeconds, expiresAtUnixSeconds, limits);
  return {
    capability,
    signature: await signCanonical(parentSubjectKey, OWNER_CAPABILITY_DOMAIN, await capabilityBody(capability))
  };
}
async function verifyCapabilityChain(state, chain, nowUnixSeconds, limits) {
  if (chain.length === 0) {
    fail("INVALID", "authorization bundle has no capabilities");
  }
  const verified = [];
  for (const signed of chain) {
    const capability = requireValue(signed.capability, "SignedOwnerCapability.capability");
    validateCapability(capability, limits);
    if (!bytesEqual(capability.capabilityId, await digest(OWNER_CAPABILITY_DOMAIN, await capabilityWithoutId(capability)))) {
      fail("INVALID", "capability id does not match canonical body");
    }
    if (!bytesEqual(capability.ownerId, state.ownerId) || nowUnixSeconds < capability.notBeforeUnixSeconds || nowUnixSeconds > capability.expiresAtUnixSeconds) {
      fail("EXPIRED", "owner capability is outside its validity interval");
    }
    let signer;
    const parent = verified.at(-1);
    if (parent) {
      const parentBody = parent.capability;
      if (!bytesEqual(capability.parentCapabilityId, parentBody.capabilityId) || !bytesEqual(capability.issuerStateHash, parentBody.issuerStateHash) || capability.notBeforeUnixSeconds < parentBody.notBeforeUnixSeconds || capability.expiresAtUnixSeconds > parentBody.expiresAtUnixSeconds || !grantCovers(parentBody.grants, capability.grants)) {
        fail("CAPABILITY_DENIED", "child capability widens or detaches from its parent");
      }
      signer = requireValue(requireValue(parentBody.subject, "OwnerCapability.subject").key, "CapabilityPrincipal.key");
    } else {
      if (capability.parentCapabilityId.byteLength !== 0) {
        fail("BROKEN_CHAIN", "first capability is not a direct owner grant");
      }
      signer = state.issuerAt(capability.issuerStateHash, nowUnixSeconds);
    }
    await verifySignature(signer, requireValue(signed.signature, "SignedOwnerCapability.signature"), OWNER_CAPABILITY_DOMAIN, await capabilityBody(capability));
    verified.push(new VerifiedCapability(signed));
  }
  return verified;
}
async function verifyAuthorizationBundle(bundle, nowUnixSeconds, limits) {
  let state = await verifyOwnerRoot(requireValue(bundle.ownerRoot, "OwnerAuthorizationBundle.ownerRoot"));
  for (const transition of bundle.ownerStateChain) {
    state = await applyTransition(state, transition, nowUnixSeconds, limits);
  }
  const chain = await verifyCapabilityChain(state, bundle.capabilityChain, nowUnixSeconds, limits);
  const leaf = chain.at(-1);
  if (!leaf)
    fail("INVALID", "authorization bundle has no leaf capability");
  await verifySubjectBiscuit(leaf.capability, bundle.subjectBiscuit);
  return new VerifiedAuthorizationBundle(state, leaf);
}
async function createAuthorizationBundle(ownerRoot, ownerStateChain, capabilityChain, subjectKey) {
  const leaf = requireValue(capabilityChain.at(-1)?.capability, "OwnerAuthorizationBundle.capabilityChain leaf");
  const subject = requireValue(leaf.subject, "OwnerAuthorizationBundle.capabilityChain leaf subject");
  const anyAnonymous = subject.kind === 5 /* AnyAnonymous */;
  if (anyAnonymous !== (subjectKey === undefined)) {
    fail("INVALID", anyAnonymous ? "ANY_ANONYMOUS bundle must not have a subject signing key" : "authorization bundle requires the leaf subject signing key");
  }
  return {
    ownerRoot,
    ownerStateChain,
    capabilityChain,
    subjectBiscuit: subjectKey === undefined ? new Uint8Array : await mintSubjectBiscuit(leaf, subjectKey)
  };
}
async function createOwnerAuthorizationSubmission(authorization, clientOperationId, nowUnixSeconds, limits) {
  if (clientOperationId.length === 0) {
    fail("INVALID", "owner authorization submission has no operation id");
  }
  await verifyAuthorizationBundle(authorization, nowUnixSeconds, limits);
  return { authorization, clientOperationId };
}
function pathsEqual(left, right) {
  return left.length === right.length && left.every((segment, index) => segment === right[index]);
}
function pathStartsWith(path, prefix) {
  return path.length >= prefix.length && prefix.every((segment, index) => path[index] === segment);
}
// src/lib/owner-authorization/limits.ts
function verificationLimits(maxCapabilityTtlSeconds, maxAnonymousTtlSeconds, maxKeyringBytes) {
  if (maxCapabilityTtlSeconds <= 0n || maxAnonymousTtlSeconds <= 0n || !Number.isSafeInteger(maxKeyringBytes) || maxKeyringBytes <= 0) {
    fail("INVALID", "verification limits must all be positive");
  }
  return {
    maxCapabilityTtlSeconds,
    maxAnonymousTtlSeconds,
    maxKeyringBytes
  };
}
export {
  exports_wire as wire,
  verificationLimits,
  exports_types as types,
  exports_root as rootModule,
  exports_recovery as recovery,
  exports_crypto as cryptoModule,
  exports_capability as capability,
  exports_canonical as canonical
};

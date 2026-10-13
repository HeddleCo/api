import { MandatoryProtocolFeature, type ProtocolCompatibility } from "../common/contract_pb.js";
import type { EntityRef } from "./common_pb.js";
import type { OpenDiscussionRequest, AppendDiscussionRequest, PutContextRequest, ResolveDiscussionRequest } from "./collaboration_pb.js";
import type { ReadContentRequest } from "./content_pb.js";

/** Support from DescribeEndpoint on this authenticated peer; discard on replacement. */
export function hostSupports(peer: ProtocolCompatibility | undefined, feature: MandatoryProtocolFeature): boolean {
  return feature !== MandatoryProtocolFeature.UNSPECIFIED && !!peer?.mandatoryFeatures.includes(feature);
}
export class MissingProtocolFeatureError extends Error {
  constructor(readonly feature: MandatoryProtocolFeature) {
    super(`Peer does not advertise protocol feature ${MandatoryProtocolFeature[feature]}`);
    this.name = "MissingProtocolFeatureError";
  }
}
export function requireFeature(peer: ProtocolCompatibility | undefined, feature: MandatoryProtocolFeature): void {
  if (!hostSupports(peer, feature)) throw new MissingProtocolFeatureError(feature);
}

/** Delivery check used automatically by the typed client before protobuf encoding.
 * Signing helpers separately check before signing; hosts verify correspondence. */
export function validateRequestFeatures(path: string, request: object, peer?: ProtocolCompatibility): void {
  const mentions = (refs: readonly EntityRef[]) => {
    if (refs.some(r => r.entity.case === "principal" || r.entity.case === "source")) requireFeature(peer, MandatoryProtocolFeature.COLLABORATION_MENTIONS_V1);
  };
  switch (path) {
    case "/heddle.api.v1alpha2.CollaborationService/OpenDiscussion": {
      const r = request as OpenDiscussionRequest;
      mentions(r.mentions);
      if (r.tags.length) requireFeature(peer, MandatoryProtocolFeature.DISCUSSION_TAGS_V1);
      break;
    }
    case "/heddle.api.v1alpha2.CollaborationService/AppendTurn": mentions((request as AppendDiscussionRequest).mentions); break;
    case "/heddle.api.v1alpha2.CollaborationService/PutContext": mentions((request as PutContextRequest).context?.mentions ?? []); break;
    case "/heddle.api.v1alpha2.CollaborationService/ResolveDiscussion": {
      const r = request as ResolveDiscussionRequest;
      if (r.resolution.case === "extractContext") mentions(r.resolution.value.mentions);
      break;
    }
    case "/heddle.api.v1alpha2.CollaborationService/EditDiscussionTags": requireFeature(peer, MandatoryProtocolFeature.DISCUSSION_TAGS_V1); break;
    case "/heddle.api.v1alpha2.ContentService/ReadContent": {
      if ((request as ReadContentRequest).selections.some(s => s.selection.case === "outline")) requireFeature(peer, MandatoryProtocolFeature.CONTENT_OUTLINE_V1);
      break;
    }
  }
}

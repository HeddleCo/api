/** Native source codecs/closure semantics are separate from signed records.
 * Consumers must derive requirements from actual objects as well as openings. */
import { NativeSourceFormat } from "../common/source_format_pb.js";

export const STATE_V6_ATTRIBUTION_V1 = NativeSourceFormat.STATE_V6_ATTRIBUTION_V1;

/** Empty advertisements never permit format-6/HCS3. Unknown requirements fail
 * closed; unknown advertisements cannot substitute for a recognized bundle. */
export function requireNativeSourceFormats(required: readonly number[], understood: readonly number[]): void {
  const seen = new Set<number>();
  for (const format of required) {
    if (format !== STATE_V6_ATTRIBUTION_V1) throw new Error(`Invalid or unsupported required native source format ${format}`);
    if (seen.has(format)) throw new Error(`Duplicate required native source format ${format}`);
    if (!understood.includes(format)) throw new Error(`Peer does not support required native source format ${format}; upgrade the peer, never strip attribution`);
    seen.add(format);
  }
}

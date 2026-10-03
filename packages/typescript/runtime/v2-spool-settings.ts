import { clone, create, equals } from "@bufbuild/protobuf";
import type { FieldMask } from "@bufbuild/protobuf/wkt";
import { SpoolSettingsSchema, type SpoolSettings } from "./administration_pb.js";
import { ThreadRefSchema, RecordRefSchema } from "./common_pb.js";

export class SpoolSettingsPatchError extends Error {
  constructor(readonly reason: "mask" | "clearDenied") {
    super(`Invalid settings ${reason}`);
    this.name = "SpoolSettingsPatchError";
  }
}

/** Atomic mask patch. canClear checks read AND clear permission on the current
 * stored value, also when either filtered reference is replaced. Equal references
 * do not remove a value. Hosts validate the new target independently, bind the
 * stored-value check and update to the same expected_version, and recheck live
 * authorization at atomic commit, including administrator/audience/policy checks. */
export function applySpoolSettingsPatch(current: SpoolSettings, patch: SpoolSettings | undefined,
  mask: Pick<FieldMask, "paths"> | undefined, canClear: (field: string) => boolean): SpoolSettings {
  const result = clone(SpoolSettingsSchema, current);
  const empty = create(SpoolSettingsSchema);
  const values = clone(SpoolSettingsSchema, patch ?? empty);
  const seen = new Set<string>();
  for (const path of mask?.paths ?? []) {
    const field = SpoolSettingsSchema.fields.find((field) => field.name === path);
    if (!field || seen.has(path)) throw new SpoolSettingsPatchError("mask");
    seen.add(path);
    const property = field.localName as keyof Omit<SpoolSettings, "$typeName">;
    const replacesReference = path === "default_thread"
      ? current.defaultThread !== undefined && (values.defaultThread === undefined
        || !equals(ThreadRefSchema, current.defaultThread, values.defaultThread))
      : path === "default_review_policy" && current.defaultReviewPolicy !== undefined
        && (values.defaultReviewPolicy === undefined
          || !equals(RecordRefSchema, current.defaultReviewPolicy, values.defaultReviewPolicy));
    if ((values[property] === empty[property] || replacesReference) && !canClear(path)) throw new SpoolSettingsPatchError("clearDenied");
    // The descriptor proves that the source/destination property has the same type.
    Object.assign(result, { [property]: values[property] });
  }
  return result;
}

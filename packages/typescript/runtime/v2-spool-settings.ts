import { clone, create } from "@bufbuild/protobuf";
import type { FieldMask } from "@bufbuild/protobuf/wkt";
import { SpoolSettingsSchema, type SpoolSettings } from "./administration_pb.js";

export class SpoolSettingsPatchError extends Error {
  constructor(readonly reason: "mask" | "clearDenied") {
    super(`Invalid settings ${reason}`);
    this.name = "SpoolSettingsPatchError";
  }
}

/** Atomic mask patch. canClear checks read AND clear permission on the current
 * stored value. Hosts own administrator/CAS checks, reference validation and
 * resulting audience/review policy validation; filtered values are not authority. */
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
    if (values[property] === empty[property] && !canClear(path)) throw new SpoolSettingsPatchError("clearDenied");
    // The descriptor proves that the source/destination property has the same type.
    Object.assign(result, { [property]: values[property] });
  }
  return result;
}

import { MandatoryProtocolFeature, type ProtocolCompatibility } from "../common/contract_pb.js";
import { requireFeature } from "./protocol.js";
import { toBinary } from "@bufbuild/protobuf";
import { type OutlineRead, type OutlineSymbol, OutlineSymbolSchema } from "./content_pb.js";
import { Coverage, SectionStatusReason, type SectionStatus } from "./common_pb.js";
import { SymbolKind, SymbolKindSchema } from "../common/repository_pb.js";

export const DEFAULT_OUTLINE_PAGE_SIZE = 100;
export const MAX_OUTLINE_PAGE_SIZE = 256;
export const MAX_OUTLINE_SYMBOL_BYTES = 16384;
const utf8 = new TextEncoder();
function bounded(value: string, nonempty = false) {
  if (utf8.encode(value).length > 4096 || /[\p{Cc}]/u.test(value) || (nonempty && !value.trim())) throw new Error("Invalid outline text");
}
export function validateOutlineRead(read: OutlineRead, peer?: ProtocolCompatibility): void {
  requireFeature(peer, MandatoryProtocolFeature.CONTENT_OUTLINE_V1);
  bounded(read.path, true);
  if (/[\\:]/.test(read.path) || read.path.split("/").some(p => p === "" || p === "." || p === "..")) throw new Error("Invalid outline path");
  if (read.page && (read.page.size > MAX_OUTLINE_PAGE_SIZE || read.page.afterPage.length > 4096)) throw new Error("Outline page exceeds bounds");
}
export function validateOutlineSymbol(symbol: OutlineSymbol): void {
  bounded(symbol.name, true); bounded(symbol.container); bounded(symbol.symbolId, true);
  if (symbol.kind === SymbolKind.UNSPECIFIED || !SymbolKindSchema.values.some(value => value.number === symbol.kind) || symbol.startLine < 1 || symbol.endLine < symbol.startLine
      || !Number.isInteger(symbol.startLine) || !Number.isInteger(symbol.endLine) || symbol.endLine > 4294967295) throw new Error("Invalid outline symbol");
  if (toBinary(OutlineSymbolSchema, symbol).length > MAX_OUTLINE_SYMBOL_BYTES) throw new Error("Outline symbol exceeds bounds");
}
export function validateOutlineStatus(status: SectionStatus): void {
  if (status.section !== "outline" || !status.computedFor || !status.page) throw new Error("Missing outline completion");
  if (![Coverage.COMPLETE, Coverage.PARTIAL, Coverage.UNAVAILABLE].includes(status.coverage)) throw new Error("Invalid outline coverage");
  if ((status.coverage === Coverage.COMPLETE) !== (status.reason === SectionStatusReason.UNSPECIFIED)) throw new Error("Invalid outline coverage reason");
  if (status.coverage === Coverage.UNAVAILABLE && (!status.page.exhausted || status.page.nextPage.length || status.page.matchingCount !== undefined)) throw new Error("Unavailable outline cannot claim indexed candidates");
  if (status.page.exhausted && status.page.nextPage.length) throw new Error("Exhausted outline has a continuation");
}

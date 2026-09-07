import {
  create, fromBinary, getOption, toBinary,
  type DescMethod, type DescService, type MessageInitShape, type MessageShape,
} from "@bufbuild/protobuf";
import { rpc_contract } from "../v1alpha1/contract_pb.js";

export interface CallOptions {
  signal?: AbortSignal;
  deadline?: Date;
}

/** Adapter owns authentication, signing exact request bytes, Iroh framing and
 * transport failures. open() must pull requests on demand and return/cancel its
 * Iroh stream when the response iterator is returned. It never redirects a
 * mutation to another device or automatically retries an ambiguous write.
 */
export interface RpcTransport {
  unary(method: DescMethod, request: Uint8Array, options?: CallOptions): Promise<Uint8Array>;
  open(method: DescMethod, requests: AsyncIterable<Uint8Array>, options?: CallOptions): AsyncIterable<Uint8Array>;
}

type Input<M extends DescMethod> = M["methodKind"] extends "client_streaming" | "bidi_streaming"
  ? AsyncIterable<MessageInitShape<M["input"]>> : MessageInitShape<M["input"]>;
type Output<M extends DescMethod> = M["methodKind"] extends "server_streaming" | "bidi_streaming"
  ? AsyncIterable<MessageShape<M["output"]>> : Promise<MessageShape<M["output"]>>;
export type ServiceClient<S extends DescService> = {
  [K in keyof S["method"]]: (input: Input<S["method"][K]>, options?: CallOptions) => Output<S["method"][K]>;
};

export class ContractClientError extends Error {
  constructor(readonly reason: "not_implemented" | "operation_id_missing" | "response_cardinality", readonly method: string) {
    super(`${method}: ${reason}`);
    this.name = "ContractClientError";
  }
}

export function methodPath(method: DescMethod): string {
  return `/${method.parent.typeName}/${method.name}`;
}

/** Typed client generated directly from protobuf service descriptors. The
 * implemented set comes from the authenticated endpoint's negotiated capability
 * result, never from service maturity or the compiled method list.
 */
export function createServiceClient<S extends DescService>(
  service: S, transport: RpcTransport, implemented: ReadonlySet<string>,
): ServiceClient<S> {
  const methods: Record<string, unknown> = {};
  for (const method of service.methods) {
    const path = methodPath(method);
    const contract = getOption(method, rpc_contract);
    function encode(input: MessageInitShape<typeof method.input>, first: boolean): Uint8Array {
      if (!implemented.has(path)) throw new ContractClientError("not_implemented", path);
      const message = create(method.input, input);
      if (first && contract.clientOperationIdRequired) {
        const id = Reflect.get(message, "clientOperationId");
        if (typeof id !== "string" || id.trim().length === 0) {
          throw new ContractClientError("operation_id_missing", path);
        }
      }
      return toBinary(method.input, message);
    }
    if (method.methodKind === "unary") {
      methods[method.localName] = async (input: MessageInitShape<typeof method.input>, options?: CallOptions) =>
        fromBinary(method.output, await transport.unary(method, encode(input, true), options));
      continue;
    }
    const stream = async function* (
      input: MessageInitShape<typeof method.input> | AsyncIterable<MessageInitShape<typeof method.input>>,
      options?: CallOptions,
    ) {
      if (!implemented.has(path)) throw new ContractClientError("not_implemented", path);
      const requests = async function* () {
        if (method.methodKind === "server_streaming") {
          yield encode(input as MessageInitShape<typeof method.input>, true);
        } else {
          let first = true;
          for await (const message of input as AsyncIterable<MessageInitShape<typeof method.input>>) {
            yield encode(message, first);
            first = false;
          }
          if (first && contract.clientOperationIdRequired) throw new ContractClientError("operation_id_missing", path);
        }
      };
      for await (const bytes of transport.open(method, requests(), options)) {
        yield fromBinary(method.output, bytes);
      }
    };
    methods[method.localName] = method.methodKind === "client_streaming"
      ? async (input: AsyncIterable<MessageInitShape<typeof method.input>>, options?: CallOptions) => {
        let result: MessageShape<typeof method.output> | undefined;
        for await (const message of stream(input, options)) {
          if (result !== undefined) throw new ContractClientError("response_cardinality", path);
          result = message;
        }
        if (result === undefined) throw new ContractClientError("response_cardinality", path);
        return result;
      }
      : stream;
  }
  // The mapping uses each descriptor's localName and cardinality, the same
  // information that defines ServiceClient<S>; it does not infer runtime types.
  return methods as ServiceClient<S>;
}

/** Small task-specific tool catalog; schemas, effects, authorization and retries
 * come from the canonical descriptor rather than a second agent API inventory.
 * Scope-level permission/readiness still comes from the current domain view.
 */
export function describeTools(
  services: readonly DescService[], implemented: ReadonlySet<string>, selected: ReadonlySet<string>,
) {
  return services.flatMap((service) => service.methods)
    .filter((method) => implemented.has(methodPath(method)) && selected.has(methodPath(method)))
    .map((method) => ({
      path: methodPath(method), input: method.input, output: method.output,
      streaming: method.methodKind, contract: getOption(method, rpc_contract),
    }));
}

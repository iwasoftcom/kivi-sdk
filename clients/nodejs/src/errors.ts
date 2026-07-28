// Honest refusals, typed (same shape as every other kivi SDK): a missing
// cell throws NotFoundError, never resolves to a fabricated null/undefined.

export class KiviError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KiviError";
  }
}

export class NotFoundError extends KiviError {}
export class UnauthenticatedError extends KiviError {}
export class PreconditionFailedError extends KiviError {}
export class InvalidArgumentError extends KiviError {}
export class UnavailableError extends KiviError {}
export class RateLimitedError extends KiviError {}

/** grpc-js status codes (mirrored here to avoid a type import cycle). */
const enum Code {
  NOT_FOUND = 5,
  UNAUTHENTICATED = 16,
  FAILED_PRECONDITION = 9,
  INVALID_ARGUMENT = 3,
  UNAVAILABLE = 14,
  RESOURCE_EXHAUSTED = 8,
}

export function wrapGrpcError(e: { code?: number; details?: string; message?: string }): KiviError {
  const msg = e.details || e.message || "unknown error";
  switch (e.code) {
    case Code.NOT_FOUND:
      return new NotFoundError(msg);
    case Code.UNAUTHENTICATED:
      return new UnauthenticatedError(msg);
    case Code.FAILED_PRECONDITION:
      return new PreconditionFailedError(msg);
    case Code.INVALID_ARGUMENT:
      return new InvalidArgumentError(msg);
    case Code.UNAVAILABLE:
      return new UnavailableError(msg);
    case Code.RESOURCE_EXHAUSTED:
      return new RateLimitedError(msg);
    default:
      return new KiviError(msg);
  }
}

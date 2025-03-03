/* tslint:disable */
/* eslint-disable */
export function keypair(): Keys;
export function verify(sig: Uint8Array, msg: Uint8Array, public_key: Uint8Array): boolean;
export class Keys {
  free(): void;
  constructor();
  sign(msg: Uint8Array): Uint8Array;
  static restore(_public: Uint8Array, secret: Uint8Array): Keys;
  readonly pubkey: Uint8Array;
  readonly secret: Uint8Array;
}
export class Params {
  private constructor();
  free(): void;
  readonly publicKeyBytes: number;
  readonly secretKeyBytes: number;
  readonly signBytes: number;
  static readonly publicKeyBytes: number;
  static readonly secretKeyBytes: number;
  static readonly signBytes: number;
}

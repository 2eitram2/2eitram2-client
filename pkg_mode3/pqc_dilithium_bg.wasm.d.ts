/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const __wbg_keys_free: (a: number, b: number) => void;
export const keypair: () => number;
export const keys_pubkey: (a: number) => [number, number];
export const keys_secret: (a: number) => [number, number];
export const keys_sign: (a: number, b: number, c: number) => [number, number];
export const keys_restore: (a: number, b: number, c: number, d: number) => [number, number, number];
export const verify: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
export const __wbg_params_free: (a: number, b: number) => void;
export const __wbg_get_params_publicKeyBytes: (a: number) => number;
export const __wbg_get_params_secretKeyBytes: (a: number) => number;
export const __wbg_get_params_signBytes: (a: number) => number;
export const params_publicKeyBytes: () => number;
export const params_secretKeyBytes: () => number;
export const params_signBytes: () => number;
export const keys_new: () => number;
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_export_2: WebAssembly.Table;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_start: () => void;

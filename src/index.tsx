const Securecrypto = require('./NativeSecurecrypto').default;

export function multiply(a: number, b: number): number {
  return Securecrypto.multiply(a, b);
}

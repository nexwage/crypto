export type AeadEnvelopeV1 = {
  v: 1;
  nonce: string;
  ct: string;
};

export type PasswordKdfParamsV1 = {
  v: 1;
  salt: string;
  opslimit: number;
  memlimit: number;
};

export type PasswordWrappedKeyV1 = {
  v: 1;
  kdf: PasswordKdfParamsV1;
  nonce: string;
  ct: string;
};

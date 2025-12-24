declare module "libsodium-wrappers-sumo" {
  import sodiumType from "libsodium-wrappers";
  const sodium: typeof sodiumType;
  export default sodium;
  export * from "libsodium-wrappers";
}

import {
  aesDecrypt,
  aesEncrypt,
  extractPrivateKey,
  extractPublicKey,
  generateAESKey,
  rsaDecrypt,
  rsaEncrypt,
  passwordDecrypt,
  passwordEncrypt, pbeDecrypt, pbeEncrypt,
} from "../src/Encryption";
import * as crypto from "crypto";

describe("Encryption", () => {
  const expected = "This is only a test.";
  const message = Buffer.from(new TextEncoder().encode(expected));
  const decoder = new TextDecoder();
  const salt = Buffer.from(crypto.getRandomValues(new Uint8Array(16)));
  describe("Asymmetric-key encryption and decryption (RSA-OAEP)", () => {
    test("With an encrypted private key", async () => {
      const privateKey = await extractPrivateKey(encryptedPrivateKeyPEM, "^1GRK2&wlSRQSao*");
      const publicKey = await extractPublicKey(publicKeyPEM);
      const encrypted = await rsaEncrypt(publicKey, message);
      const decrypted = await rsaDecrypt(privateKey, encrypted);
      expect(decoder.decode(decrypted)).toEqual(expected);
    });
    test("With an unencrypted private key", async () => {
      const privateKey = await extractPrivateKey(unencryptedPrivateKeyPEM);
      const publicKey = await extractPublicKey(publicKeyPEM);
      const encrypted = await rsaEncrypt(publicKey, message);
      const decrypted = await rsaDecrypt(privateKey, encrypted);
      expect(decoder.decode(decrypted)).toEqual(expected);
    });
    test("Decrypt data encrypted in Java", async () => {
      const decryptedPrivateKey = await extractPrivateKey(encryptedPrivateKeyPEM, "^1GRK2&wlSRQSao*");
      const privateKey = await extractPrivateKey(unencryptedPrivateKeyPEM);
      const encrypted = Buffer.from("xPKpvKYqxpKsKdqyny0v5OLGci1olCCl6PSVnH353vQWBDpMzfEgM8B1EZhKkoaGdov/E6/+V1ZXhGmGlZX9qjVScvxoUAJlE7mPD1pJm2K2laUxGiFWs/jiYf4S05aR2Bpdeb6YO1Dhb1mcXKJmb/tOydCyRc8+tSpWbDYdH9sPWcI81bBXViGrVroytPT7o4nlA0v9+cRG2Vk7PeAV9RD42pdt4sZliZaTGlz97JyyPOkVqAEToIlwFTW8rFraqAVnPRw0iAotfHF6qWWCd3hoiBD5Rvb76AI+MaP2DbnYOCOA8Z2e5KAeoYODG30WaaclnMg+jlAlkhehM5wZuw==", "base64");
      expect(decoder.decode(await rsaDecrypt(privateKey, encrypted))).toEqual("This is only a test.");
      expect(decoder.decode(await rsaDecrypt(decryptedPrivateKey, encrypted))).toEqual("This is only a test.");
    });
  });
  describe("Jasypt interoperability", () => {
    test("Decrypting data encrypted with Jasypt", async () => {
      const encrypted = "93NreftgVZPwHN19bunzWquJgO5fHQ06jxRb9+rVOwftEpKWRtzsNroYXtMgmpkHRKRmqbOXoLt1s4k39cPt3w==";
      const decrypted = await pbeDecrypt("testPassword", Buffer.from(encrypted, "base64"));
      expect(decoder.decode(decrypted)).toEqual("This is only a test.");
    });
  });
  describe("Password-based encryption", () => {
    test("Encrypting and decrypting with the same password", async () => {
      const encrypted = await pbeEncrypt("testPassword", message);
      const decrypted = await pbeDecrypt("testPassword", encrypted);
      expect(decoder.decode(decrypted)).toEqual(expected);
    });
  });
  describe("Symmetric-key encryption and decryption (AES-CBC-256)", () => {
    test("Encrypting and decrypting with the same key", async () => {
      const key = await generateAESKey("f%UNLck19dtiiFvo", salt);
      const encrypted = await aesEncrypt(key, message);
      const decrypted = await aesDecrypt(key, encrypted);
      expect(decoder.decode(decrypted)).toEqual(expected);
    });
    test("Encrypting and decrypting with different keys (correct passphrase)", async () => {
      const key = await generateAESKey("f%UNLck19dtiiFvo", salt);
      const encrypted = await aesEncrypt(key, message);
      const decrypted = await aesDecrypt(await generateAESKey("f%UNLck19dtiiFvo", salt), encrypted);
      expect(decoder.decode(decrypted)).toEqual(expected);
    });
    test("Encrypting and decrypting with implicit salt (SHA-256 of passphrase)", async () => {
      const key = await generateAESKey("f%UNLck19dtiiFvo");
      const encrypted = await aesEncrypt(key, message);
      const decrypted = await aesDecrypt(key, encrypted);
      expect(decoder.decode(decrypted)).toEqual(expected);
    });
    test("Decrypt data encrypted in Java", async () => {
      const key = await generateAESKey("f%UNLck19dtiiFvo");
      const encrypted = Buffer.from("AL+FNCaWG1u2Yw9bepxzWu6zjTfwpXpvQXzNMhexmRu9tKbMreuxvpXvsc2XYFB3", "base64");
      const decrypted = await aesDecrypt(key, encrypted);
      expect(decoder.decode(decrypted)).toEqual("This is only a test.");
    });
  });
  describe("Password-based encryption and decryption (AES-CBC-256/PBEWithHmacSHA256AndAES_256)", () => {
    test("Decrypt data encrypted in Java", async () => {
      const encrypted = Buffer.from("fV7lASQ7gfRujNdVLl4dWE00ZVOAvewmghzs9QYhoAY=", "base64");
      const decrypted = await passwordDecrypt("testPasswordInJava", encrypted);
      expect(decoder.decode(decrypted)).toEqual("This is only a test.");
    });
    test("Encrypting and decrypting with the same password", async () => {
      const encrypted = await passwordEncrypt("testPasswordInJavascript", message);
      const decrypted = await passwordDecrypt("testPasswordInJavascript", encrypted);
      expect(decoder.decode(decrypted)).toEqual(expected);
    });
    test("Encrypting and decrypting with the same password and provided iv and salt", async () => {
      const iv = Buffer.from("abcdefghijklmnop");
      const salt = Buffer.from("bcdefghijklmnopq");
      const encrypted = await passwordEncrypt("testPasswordInJavascript", message, salt, iv);
      const decrypted = await passwordDecrypt("testPasswordInJavascript", encrypted, salt, iv);
      expect(decoder.decode(decrypted)).toEqual(expected);
    });
  });

  /* Encrypted private key. */
  const encryptedPrivateKeyPEM = [
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI/YDolrf6hbUCAggA",
    "MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBD89fo3YS6+g33bPbfBe0oHBIIE",
    "0EOMlDNc9LINlDRLAp4YiG5GfPsehxBHnzPGZ/kXGXmkhidZH2OZDFS9f2CJTbgY",
    "QkR01sNfObnX2Uxj24GmEahcCGwYOxO+Rs0Rxs2/HCupVG+4iHsHMLeHbzfClTm+",
    "ey2VaaC29vdpZIXfddv/sIBY35y3Qxaj0oxAk7p2/jIu5tgISjcjLroL66UyaECd",
    "rg7bJ/FoGLhCLAq1T0jkD7c5IaIsWV/GuXyjtSb/CWfPTgvQIkyfBdrWZ/PRHX48",
    "PA+b2PSUrra4/Hdh7Pa3tHE05tTf4pMSDmiG2hIeHr6WXKocSQHBrIZ3AarDBGts",
    "0o6tWoi5TswnALbDsGI8nJsnCXjTTp4cwWLMILBKUN88PbvOZrSUsfg+n5tfuqU9",
    "1umSnO+FirKYlWmjXS3lEx8OSLMZKGCQi4rC2Nd/k7YK+Zc05bpoqDN0VzVx6L8C",
    "1S5vVPlnpl9/ZFXwMJ8xKh0UfOpn6w9FVouVC97w1cz8C9DBrxKIEPf5D+Y6OxbQ",
    "FMWysB58QJLAKCEnmNDEBX21gy8bCAPnGne8WJ08p0Qm7IZYmZ8QXOpvmbbFVoyO",
    "yFV9xN26AOdNRTt2CMCxTA/mXeWo48VgAjnPzBCUNvQmtxiwppYZfuAA4euJV0Cv",
    "hur/zfciD/2ndiKWbchAtNiwzHtghnX0iZy5sfC/z27QOukEHOUdSqkMSS80Z+8o",
    "yMOR760JwNe8O72Mdm19m+H4wyr+SGQEhT6MQuuTqd9fOf+23GjdGPvDCGoz0/yg",
    "Y720MhFJLV3o0giSgqJVsZJCNI4ql+tWyysvWKXThEi9XYlmV7ZtPN+gzjEgArKG",
    "V0KHvpG6v++eKkKllDooGTIyynGEmkmiEUlPXkIh7u98AAz/DlS16f8P2f6JQ5kH",
    "eAaDAlsvWGbaY52fBXKg3J4krAnd5sY7QltgCxWpNZMKiQYuuDW1WzzoeoofUaBi",
    "Bqr56oHoOzEYhvYtoEOxzJiay9Dhmgbskzs1PwEaFiPJsm78rodDciwLPdJy5oaH",
    "dpmluGI2n1sts40E4rPV6bMQ49YZ4cXpv4H4GB2dnfOlhisCM8mXYUagyp+/MUDM",
    "Itk4C2Alp+Faft7I/uKrTWd8e5TsI7vQApmO0gcee/ruCQApNs7uHJljlAeuN3qi",
    "whYACB97Qg7fumh02FG5zI6G0FG61sJhESCaTmZUDY/A0OEVGRIukHtZduX+s9iJ",
    "Vskc8/eoV4LeIjGwylyTu0rfaBAGa2uKIRx+L08mqZN4ZtDVBS7gIziLXw1gilrK",
    "boHsIDfO/UvN0U4Liwgbalo8vIHjz8ntX8or5BUE0G5KUT/1yF0cjJXoTyv55Eyq",
    "659FWUlMB0fTFsnRnuyK3E1zo1wLrGw4uLGXvEj+n6jxaq4CWUUOv2FTEKW6d+vu",
    "iMGRRxBipX1g5kDqexNOiR/4MS0nWIT7YyjqMVrt5SpakK60PzYxnaTvPP7hesKH",
    "T9CA3Q0P2p7SCauclCv3BtHNvatiBRwOXJNSjDZkbinzaUTQXhZ3EkNA8BO+HRVJ",
    "NqxS9DKFXinMBvxdSxTVsdaWEAKhIQanZuVFogqjG94+J6BkqaJos2evtkGGaz7W",
    "n5YXHVnfG7ZHM4vAT/M40F1mQcO5ctQdKAzEMQFXl7+z",
    "-----END ENCRYPTED PRIVATE KEY-----",
  ].join("\n");

  /* Public key corresponding to [un]encryptedPrivateKeyPEM. */
  const publicKeyPEM = [
    "-----BEGIN PUBLIC KEY-----",
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyf4KnwPbZ5NNN0qxBj+5",
    "VSr2g1D/go/yh1YNGWZ/bgva9yNknyACKrcXUORbaq00R1s9Cw2IK7w9VkT775xW",
    "qJ/midxfYMcZ/SYcXsNMqHvrMQdR6o3Mi0FbvKFb3V9ar7+6ZzSa3wKlN9vCy6Zs",
    "AQuMEI/LlV1RrUjQ7kORSnJz16Q2m9A8UFgzNxGCUBBEXOzZoBVnNMdE7Yi0VwDQ",
    "/zk8hQwUPu9iykFmcFSRg8fHStx5zRS2xRhUdEVJnXGP7CRrZRqQiA/F/2TK/35X",
    "gNfOv+iauxEsfirKOvleTzWQsVil5gesaYtOqRVYyZptVn1hwgUF/Yf53i586WbN",
    "0wIDAQAB",
    "-----END PUBLIC KEY-----",
  ].join("\n");

  /* Same private key as encryptedPrivateKeyPEM but with encryption removed. */
  const unencryptedPrivateKeyPEM = [
    "-----BEGIN PRIVATE KEY-----",
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJ/gqfA9tnk003",
    "SrEGP7lVKvaDUP+Cj/KHVg0ZZn9uC9r3I2SfIAIqtxdQ5FtqrTRHWz0LDYgrvD1W",
    "RPvvnFaon+aJ3F9gxxn9Jhxew0yoe+sxB1HqjcyLQVu8oVvdX1qvv7pnNJrfAqU3",
    "28LLpmwBC4wQj8uVXVGtSNDuQ5FKcnPXpDab0DxQWDM3EYJQEERc7NmgFWc0x0Tt",
    "iLRXAND/OTyFDBQ+72LKQWZwVJGDx8dK3HnNFLbFGFR0RUmdcY/sJGtlGpCID8X/",
    "ZMr/fleA186/6Jq7ESx+Kso6+V5PNZCxWKXmB6xpi06pFVjJmm1WfWHCBQX9h/ne",
    "LnzpZs3TAgMBAAECggEAKSCwyO/gHJbBgiCTKtKOyeiViOdVHyBwIV5EDIfyKlX/",
    "n5J1SnEZ/9iHxtC4TGA35M+O/lEjCMSrOIWTRpZujqcAKdHVGb9wazr3S9Q4J5YT",
    "rUfwRfHZVAFazG2OZuSjcmV3bswnPIEtYtI8N3sLQqs3OagNq7v0hXPuFpVrX9zR",
    "GWRpoe0uIM/KbIO9IQ5dCZqdUHuIhdGEKQpUSxz0YuCnb8ieR0BRxhtrkP8WRq1N",
    "cOQrDQj08oc4vEJBkfVQyibZZDQYW4VyS+6fWMs8Aziot/mF0x6kpH00v7jABxrx",
    "0smS9kbq9OBOnAJ7wNCIjPVyvSQc3qN3bclhy87zAQKBgQD1h4G8/KAp2CkRT9mI",
    "jftn7uoj2bPexOxba4IyJNWA2NGffX1zEeyIuG7OrWVasgABOify5BjnegqvZF2c",
    "//zfNHfaBelRAKrnUmDcalMvTc18p7pBEwm1kVWWqtqfNnODac/dXJVZJrAJRdFN",
    "JwgA4qEhdPj0KY7kWBUHewWG5QKBgQDSmzuWWpsyvPtZOdMcC4ey1okF++2jbEk5",
    "a6WP544pehtKc0wOwtTxRl2cbz0KgedPnZD/hSWEe6AnJN+8MFraeTc+SDgRL6Wt",
    "1/iqS+kR0kKSPFvSWpdG+urRZYBc38LNK2H/LXpISp8Khe5BmIOCmfYKiMWVxAFB",
    "ZO7M0Ei+VwKBgQC9ufJE6SmSbBh/6iX8YUqN644+GbHmSGEj25WFzfS1VdXV2pCf",
    "5I/Urj/hsReK19UtHZVVGXEtHZ84HORBt4XdrJuYe8zo7Q0jJwL2D6sr+ID6/Fju",
    "hBmSljV+8ZNySA9G0vLu6OX3N+/7mlm7tpd2p6k/QzZE5gAm7vGBEE0bCQKBgBQx",
    "pkkIbxEyZbdsf/2UbXKMd58HRQYCgBLta3ac8ViwyKUe4RAZRmnMIXW6hNPZGODd",
    "buXRUoOdhwG522okCNIiBVYHfrjHJM/CgalyleqLiq6S8wr8fLzlmlZxsRk2q2sY",
    "2dCp/6um3BEaPnozsYh4Uss3yhpOLQCkOPGSlycJAoGAZJ7YOk7cdh/Yad27OEyo",
    "+dDlV+b4koRA6zzU2uAh2vlYuE1npvGrsaL6qTeqqoDTRUfBcpHYQv7nFar6Y15a",
    "nxZcexrQDzApt9GKNW/rGWGTV8v3sRtO5BJRNVxggoRRnwe9W7wIP6uQBSFyM/AJ",
    "Ao2RiE/K/t0AF6P3meiWc84=",
    "-----END PRIVATE KEY-----",
  ].join("\n");
});

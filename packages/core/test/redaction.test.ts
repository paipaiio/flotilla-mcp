import { describe, expect, it } from "vitest";
import { redactSensitiveText } from "../src/redaction.js";

describe("redactSensitiveText", () => {
  it("preserves public text while replacing recognized secrets with stable fingerprints", () => {
    const source = [
      "service=ready",
      "API_TOKEN=alpha-secret-value-12345",
      "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
      "port=443",
    ].join("\n");

    const first = redactSensitiveText(source);
    const second = redactSensitiveText(source);

    expect(first.text).toContain("service=ready");
    expect(first.text).toContain("API_TOKEN=[REDACTED secret-value sha256:");
    expect(first.text).toContain("Authorization: Bearer [REDACTED bearer-token sha256:");
    expect(first.text).toContain("port=443");
    expect(first.text).not.toContain("alpha-secret-value-12345");
    expect(first.text).not.toContain("eyJhbGciOiJIUzI1NiJ9.payload.signature");
    expect(first).toEqual(second);
    expect(first.redactions).toHaveLength(2);
    expect(first.redactions.every((item) => /^[a-f0-9]{16}$/.test(item.fingerprint))).toBe(true);
  });

  it("replaces a complete private-key block without exposing its body", () => {
    const source = "before\n-----BEGIN PRIVATE KEY-----\nvery-sensitive-material\n-----END PRIVATE KEY-----\nafter";
    const result = redactSensitiveText(source);

    expect(result.text).toContain("before");
    expect(result.text).toContain("after");
    expect(result.text).toContain("[REDACTED private-key sha256:");
    expect(result.text).not.toContain("very-sensitive-material");
    expect(result.redactions).toMatchObject([{ kind: "private-key", length: expect.any(Number) }]);
  });

  it("does not treat ordinary checksums or public identifiers as secrets", () => {
    const checksum = "a".repeat(64);
    const source = `sha256=${checksum}\nrequest_id=req_1234567890\nstatus=ok`;
    expect(redactSensitiveText(source)).toEqual({ text: source, redactions: [] });
  });
});

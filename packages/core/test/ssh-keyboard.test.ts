import { describe, expect, it } from "vitest";
import { keyboardInteractiveAnswers } from "../src/ssh.js";

const p = (prompt: string) => ({ prompt, echo: false });

describe("keyboardInteractiveAnswers", () => {
  it("gives the password only to password prompts, never to 2FA / OTP prompts", () => {
    expect(keyboardInteractiveAnswers([p("Password: ")], "pw")).toEqual(["pw"]);
    expect(keyboardInteractiveAnswers([p("root@host's password:")], "pw")).toEqual(["pw"]);
    expect(keyboardInteractiveAnswers([p("密码：")], "pw")).toEqual(["pw"]);
    expect(keyboardInteractiveAnswers([p("Verification code: ")], "pw")).toEqual([""]);
    expect(keyboardInteractiveAnswers([p("One-time password (OATH) for `root':")], "pw")).toEqual([""]);
    expect(keyboardInteractiveAnswers([p("Duo two-factor login. Passcode or option (1-3):")], "pw")).toEqual([""]);
    expect(keyboardInteractiveAnswers([], "pw")).toEqual([]);
  });
});

import { describe, expect, it, vi } from "vitest";
import { redirect } from "next/navigation";
import { Prisma } from "@prisma/client";
import { z } from "zod";

import { action, publicMessage } from "@/lib/action";
import { unwrap } from "@/lib/action-result";

describe("server action results", () => {
  it("passes HELIOS's own messages through and hides internals", () => {
    expect(publicMessage(new Error("Keep logs for at least 180 days"))).toBe("Keep logs for at least 180 days");
    expect(publicMessage(z.object({ name: z.string().min(2, "Too short") }).safeParse({ name: "a" }).error)).toBe("name: Too short");
    expect(publicMessage(new Prisma.PrismaClientKnownRequestError("No record", { code: "P2025", clientVersion: "6" }))).toBe("Not found");
    const generic = /server log/;
    expect(publicMessage(new Prisma.PrismaClientKnownRequestError("Invalid `db.case.update()` invocation", { code: "P2000", clientVersion: "6" }))).toMatch(generic);
    expect(publicMessage(new TypeError("Cannot read properties of undefined (reading 'id')"))).toMatch(generic);
    expect(publicMessage(Object.assign(new Error("ENOENT: no such file, open '/srv/secret'"), { code: "ENOENT" }))).toMatch(generic);
    expect(publicMessage("a string")).toMatch(generic);
  });

  it("returns a refusal as a value, which unwrap turns back into an error", async () => {
    const quiet = vi.spyOn(console, "error").mockImplementation(() => {});
    const save = action(async (n: number) => {
      if (n < 180) throw new Error("At least 180 days");
      return n * 2;
    });
    expect(await save(200)).toEqual({ ok: true, value: 400 });
    expect(await save(90)).toEqual({ ok: false, error: "At least 180 days" });
    await expect(unwrap(save(90))).rejects.toThrow("At least 180 days");
    expect(await unwrap(save(181))).toBe(362);
    const broken = action(async () => (undefined as unknown as { id: string }).id);
    expect(await broken()).toEqual({ ok: false, error: expect.stringMatching(/server log/) });
    expect(quiet).toHaveBeenCalledTimes(1);
    quiet.mockRestore();
  });

  it("lets Next's redirects through", async () => {
    const go = action(async () => redirect("/login"));
    await expect(go()).rejects.toThrow(/NEXT_REDIRECT/);
  });
});

// The on-call rota, pure: who is on call at a moment, a rotation generated
// from a list of people, and the hours nobody covers. An override (a swap,
// sick cover) beats the regular rotation for its hours; among several, the
// latest one wins. lib/operations/paging.ts reads it.

export const ROTA_ROLES = { primary: "Primary", backup: "Backup" } as const;
export type RotaRole = keyof typeof ROTA_ROLES;

export interface Shift {
  id: string;
  userId: string;
  role: string;
  startsAt: Date;
  endsAt: Date;
  override: boolean;
  createdAt: Date;
}

const HOUR = 3_600_000;

export function onCallAt<T extends Shift>(shifts: T[], at: Date, role: RotaRole): T | null {
  const live = shifts.filter((s) => s.role === role && s.startsAt <= at && at < s.endsAt);
  const pick = (xs: T[]) => xs.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())[0] ?? null;
  return pick(live.filter((s) => s.override)) ?? pick(live.filter((s) => !s.override));
}

export interface Rotation {
  userIds: string[];
  from: Date;
  shiftHours: number;
  shifts: number;
  // Also a backup rotation: the next person in the list.
  withBackup: boolean;
}

export function generateRotation(r: Rotation): Array<Pick<Shift, "userId" | "role" | "startsAt" | "endsAt">> {
  if (!r.userIds.length) throw new Error("Choose who is on the rotation");
  if (r.withBackup && new Set(r.userIds).size < 2) throw new Error("A backup rotation needs at least two people");
  if (!(r.shiftHours >= 4 && r.shiftHours <= 24 * 14)) throw new Error("A shift is between 4 hours and two weeks");
  if (!(r.shifts >= 1 && r.shifts <= 200)) throw new Error("Generate between 1 and 200 shifts at a time");
  const out: Array<Pick<Shift, "userId" | "role" | "startsAt" | "endsAt">> = [];
  for (let i = 0; i < r.shifts; i++) {
    const startsAt = new Date(r.from.getTime() + i * r.shiftHours * HOUR);
    const endsAt = new Date(startsAt.getTime() + r.shiftHours * HOUR);
    out.push({ userId: r.userIds[i % r.userIds.length], role: "primary", startsAt, endsAt });
    if (r.withBackup) out.push({ userId: r.userIds[(i + 1) % r.userIds.length], role: "backup", startsAt, endsAt });
  }
  return out;
}

// Stretches of [from, to) with nobody on call in the role.
export function gaps(shifts: Shift[], from: Date, to: Date, role: RotaRole): Array<{ from: Date; to: Date }> {
  const spans = shifts
    .filter((s) => s.role === role && s.endsAt > from && s.startsAt < to)
    .map((s) => [Math.max(s.startsAt.getTime(), from.getTime()), Math.min(s.endsAt.getTime(), to.getTime())] as const)
    .sort((a, b) => a[0] - b[0]);
  const out: Array<{ from: Date; to: Date }> = [];
  let cursor = from.getTime();
  for (const [a, b] of spans) {
    if (a > cursor) out.push({ from: new Date(cursor), to: new Date(a) });
    cursor = Math.max(cursor, b);
  }
  if (cursor < to.getTime()) out.push({ from: new Date(cursor), to });
  return out;
}

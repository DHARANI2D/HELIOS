// India's Digital Personal Data Protection Act, 2023 and the DPDP Rules,
// 2025 (notified 13 November 2025). Rule 7: on becoming aware of a personal
// data breach, the Data Fiduciary tells each affected Data Principal and
// the Data Protection Board without delay, and sends the Board a detailed
// report within 72 hours (or longer, if the Board allows on request). Rule 7
// applies from 13 May 2027; HELIOS runs the same workflow before then, so a
// client can practise it. The fields each notice holds are in
// lib/compliance/notices.ts. Pure.

export const DPDP_REPORT_HOURS = 72;
export const DPDP_RULE7_FROM = new Date("2027-05-13T00:00:00+05:30");
export const dpdpInForce = (now = new Date()) => now >= DPDP_RULE7_FROM;

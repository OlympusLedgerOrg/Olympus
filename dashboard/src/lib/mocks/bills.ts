export type LegislationLevel = "federal" | "state" | "local";
export type LegislationStatus = "active" | "inactive";
export type VoteChoice = "yea" | "nay" | "abstain";

export type DistrictVoteTotals = {
  yea: number;
  nay: number;
  abstain: number;
};

export type BillRecord = {
  id: string;
  title: string;
  level: LegislationLevel;
  status: LegislationStatus;
  introducedAt: string;
  hotness: number;
  alignmentBaseline: number;
  sponsors: string[];
  repName: string;
  repVote: VoteChoice;
  plainEnglishSummary: string;
  areaImpact: string;
  districtTotals: Record<string, DistrictVoteTotals>;
};

export type BillFeed = {
  updatedAt: string;
  source: string;
  bills: BillRecord[];
};

export const mockBillFeed: BillFeed = {
  updatedAt: "2026-03-15T00:00:00.000Z",
  source: "Olympus symbolic legislation relay (mock)",
  bills: [
    {
      id: "hr-2041",
      title: "Public Records API Reliability Act",
      level: "federal",
      status: "active",
      introducedAt: "2026-03-10T12:00:00.000Z",
      hotness: 94,
      alignmentBaseline: 81,
      sponsors: ["Rep. Marina Soto", "Rep. Priya Rao"],
      repName: "Rep. Marina Soto",
      repVote: "yea",
      plainEnglishSummary:
        "This bill requires agencies to publish machine-readable response logs for public records requests within strict time windows.",
      areaImpact:
        "For your district, this would shorten records request wait times and expose delay patterns for local oversight teams.",
      districtTotals: {
        "WA-01": { yea: 421, nay: 109, abstain: 37 },
        "WA-02": { yea: 339, nay: 188, abstain: 41 },
        "WA-03": { yea: 386, nay: 97, abstain: 33 },
      },
    },
    {
      id: "sb-778",
      title: "State Climate Ledger Grant Program",
      level: "state",
      status: "active",
      introducedAt: "2026-03-07T18:30:00.000Z",
      hotness: 88,
      alignmentBaseline: 74,
      sponsors: ["Sen. Alana Brooks", "Sen. Damian Reid"],
      repName: "Rep. Evan Kline",
      repVote: "nay",
      plainEnglishSummary:
        "Creates a grant pool for municipalities that publish climate spending data in open ledger-compatible formats.",
      areaImpact:
        "Your county could qualify for resilience funding, but reporting requirements would increase for small local agencies.",
      districtTotals: {
        "WA-01": { yea: 302, nay: 214, abstain: 50 },
        "WA-02": { yea: 241, nay: 262, abstain: 54 },
        "WA-03": { yea: 289, nay: 201, abstain: 35 },
      },
    },
    {
      id: "c-19-204",
      title: "County Broadband Procurement Transparency",
      level: "local",
      status: "active",
      introducedAt: "2026-03-12T08:45:00.000Z",
      hotness: 76,
      alignmentBaseline: 69,
      sponsors: ["Councilmember Imani Fields", "Councilmember Theo Park"],
      repName: "Rep. Priya Rao",
      repVote: "yea",
      plainEnglishSummary:
        "Requires county broadband contracts above $250k to publish bid scoring and amendment trails in plain language.",
      areaImpact:
        "Residents would be able to compare promised service improvements against contract changes by neighborhood.",
      districtTotals: {
        "WA-01": { yea: 210, nay: 129, abstain: 24 },
        "WA-02": { yea: 187, nay: 144, abstain: 27 },
        "WA-03": { yea: 233, nay: 98, abstain: 21 },
      },
    },
    {
      id: "hr-1990",
      title: "Legacy Agency Record Retention Pilot",
      level: "federal",
      status: "inactive",
      introducedAt: "2026-01-22T16:20:00.000Z",
      hotness: 52,
      alignmentBaseline: 58,
      sponsors: ["Rep. Jonas Pike"],
      repName: "Rep. Jonas Pike",
      repVote: "abstain",
      plainEnglishSummary:
        "Pilot program for digitizing legacy paper archives before mandatory retention policy updates.",
      areaImpact:
        "Your area would see phased archive scans, but no immediate change to request turnaround times.",
      districtTotals: {
        "WA-01": { yea: 144, nay: 131, abstain: 62 },
        "WA-02": { yea: 119, nay: 166, abstain: 57 },
        "WA-03": { yea: 139, nay: 141, abstain: 49 },
      },
    },
    {
      id: "sb-640",
      title: "Open Meeting Transcript Access Rule",
      level: "state",
      status: "inactive",
      introducedAt: "2026-02-03T09:10:00.000Z",
      hotness: 47,
      alignmentBaseline: 63,
      sponsors: ["Sen. Maya Kent"],
      repName: "Rep. Marina Soto",
      repVote: "yea",
      plainEnglishSummary:
        "Mandates searchable transcript publication for committee hearings within 72 hours of adjournment.",
      areaImpact:
        "Communities in your district would gain faster access to hearing transcripts for education and housing issues.",
      districtTotals: {
        "WA-01": { yea: 198, nay: 122, abstain: 35 },
        "WA-02": { yea: 176, nay: 149, abstain: 42 },
        "WA-03": { yea: 204, nay: 121, abstain: 37 },
      },
    },
  ],
};

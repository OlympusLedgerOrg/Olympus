import type { DistrictGeometry, GeoPoint } from "@/lib/utils/districtMath";

export type Party = "D" | "R" | "I";

export type VoteAlignmentSummary = {
  aligned: number;
  opposed: number;
  abstained: number;
  lastUpdated: string;
};

export type TownHallEvent = {
  id: string;
  date: string;
  location: string;
  topic: string;
  format: "in-person" | "virtual";
  status: "scheduled" | "completed" | "registration-open";
};

export type RepContact = {
  phone: string;
  email: string;
  website: string;
  office: string;
};

export type RepresentativeProfile = {
  id: string;
  name: string;
  party: Party;
  state: string;
  district: string;
  districtName: string;
  alignmentScore: number;
  attendance: number;
  nextElection: string;
  contact: RepContact;
  voteAlignment: VoteAlignmentSummary;
  townHalls: TownHallEvent[];
  districtGeometry: DistrictGeometry;
};

export type RepFeed = {
  state: string;
  updatedAt: string;
  source: string;
  reps: RepresentativeProfile[];
};

export const mockUserLocation: GeoPoint = {
  lat: 47.71,
  lon: -122.65,
};

const mockDistricts: DistrictGeometry[] = [
  {
    id: "wa-01",
    name: "Puget Coast",
    polygon: [
      { lat: 47.95, lon: -123.2 },
      { lat: 47.95, lon: -122.8 },
      { lat: 47.6, lon: -122.8 },
      { lat: 47.6, lon: -123.2 },
    ],
    labelPosition: { lat: 47.78, lon: -123.02 },
  },
  {
    id: "wa-02",
    name: "North Sound",
    polygon: [
      { lat: 47.95, lon: -122.8 },
      { lat: 47.95, lon: -122.4 },
      { lat: 47.6, lon: -122.4 },
      { lat: 47.6, lon: -122.8 },
    ],
    labelPosition: { lat: 47.78, lon: -122.58 },
  },
  {
    id: "wa-03",
    name: "Olympic Foothills",
    polygon: [
      { lat: 47.6, lon: -123.2 },
      { lat: 47.6, lon: -122.8 },
      { lat: 47.2, lon: -122.8 },
      { lat: 47.2, lon: -123.2 },
    ],
    labelPosition: { lat: 47.4, lon: -123.02 },
  },
  {
    id: "wa-04",
    name: "Rainier East",
    polygon: [
      { lat: 47.6, lon: -122.8 },
      { lat: 47.6, lon: -122.4 },
      { lat: 47.2, lon: -122.4 },
      { lat: 47.2, lon: -122.8 },
    ],
    labelPosition: { lat: 47.4, lon: -122.58 },
  },
];

export const mockReps: RepresentativeProfile[] = [
  {
    id: "rep-soto",
    name: "Marina Soto",
    party: "D",
    state: "WA",
    district: "WA-01",
    districtName: mockDistricts[0].name,
    alignmentScore: 86,
    attendance: 94,
    nextElection: "2026-11-03",
    contact: {
      phone: "(202) 555-0142",
      email: "marina.soto@house.gov",
      website: "https://soto.house.gov",
      office: "1421 Longworth House Office Building",
    },
    voteAlignment: {
      aligned: 28,
      opposed: 6,
      abstained: 2,
      lastUpdated: "2026-03-12T18:00:00.000Z",
    },
    townHalls: [
      {
        id: "soto-01",
        date: "2026-03-27T01:00:00.000Z",
        location: "Port Madison Civic Center",
        topic: "Coastal resilience funding",
        format: "in-person",
        status: "registration-open",
      },
      {
        id: "soto-02",
        date: "2026-04-10T00:00:00.000Z",
        location: "Virtual · Live stream",
        topic: "Olympus transparency updates",
        format: "virtual",
        status: "scheduled",
      },
    ],
    districtGeometry: mockDistricts[0],
  },
  {
    id: "rep-kline",
    name: "Evan Kline",
    party: "R",
    state: "WA",
    district: "WA-02",
    districtName: mockDistricts[1].name,
    alignmentScore: 67,
    attendance: 89,
    nextElection: "2026-11-03",
    contact: {
      phone: "(202) 555-0188",
      email: "evan.kline@house.gov",
      website: "https://kline.house.gov",
      office: "1220 Rayburn House Office Building",
    },
    voteAlignment: {
      aligned: 22,
      opposed: 10,
      abstained: 3,
      lastUpdated: "2026-03-09T18:00:00.000Z",
    },
    townHalls: [
      {
        id: "kline-01",
        date: "2026-03-22T01:00:00.000Z",
        location: "Bellingham Trade Hall",
        topic: "Ferry reliability + comms resilience",
        format: "in-person",
        status: "scheduled",
      },
      {
        id: "kline-02",
        date: "2026-04-18T19:00:00.000Z",
        location: "Virtual · Access code WA02",
        topic: "Budget transparency review",
        format: "virtual",
        status: "registration-open",
      },
    ],
    districtGeometry: mockDistricts[1],
  },
  {
    id: "rep-rao",
    name: "Priya Rao",
    party: "D",
    state: "WA",
    district: "WA-03",
    districtName: mockDistricts[2].name,
    alignmentScore: 91,
    attendance: 97,
    nextElection: "2026-11-03",
    contact: {
      phone: "(202) 555-0106",
      email: "priya.rao@house.gov",
      website: "https://rao.house.gov",
      office: "221 Cannon House Office Building",
    },
    voteAlignment: {
      aligned: 31,
      opposed: 4,
      abstained: 1,
      lastUpdated: "2026-03-11T18:00:00.000Z",
    },
    townHalls: [
      {
        id: "rao-01",
        date: "2026-03-25T23:00:00.000Z",
        location: "Tacoma Civic Auditorium",
        topic: "Emergency response audits",
        format: "in-person",
        status: "registration-open",
      },
      {
        id: "rao-02",
        date: "2026-04-06T00:00:00.000Z",
        location: "Virtual · Northwest stream",
        topic: "Civic data modernization",
        format: "virtual",
        status: "scheduled",
      },
    ],
    districtGeometry: mockDistricts[2],
  },
  {
    id: "rep-pike",
    name: "Jonas Pike",
    party: "R",
    state: "WA",
    district: "WA-04",
    districtName: mockDistricts[3].name,
    alignmentScore: 72,
    attendance: 88,
    nextElection: "2026-11-03",
    contact: {
      phone: "(202) 555-0174",
      email: "jonas.pike@house.gov",
      website: "https://pike.house.gov",
      office: "1310 Longworth House Office Building",
    },
    voteAlignment: {
      aligned: 19,
      opposed: 12,
      abstained: 5,
      lastUpdated: "2026-03-10T18:00:00.000Z",
    },
    townHalls: [
      {
        id: "pike-01",
        date: "2026-03-29T01:30:00.000Z",
        location: "Yakima Regional Center",
        topic: "Infrastructure audit follow-up",
        format: "in-person",
        status: "scheduled",
      },
      {
        id: "pike-02",
        date: "2026-04-12T22:00:00.000Z",
        location: "Virtual · District hotline",
        topic: "Agricultural ledger intake",
        format: "virtual",
        status: "registration-open",
      },
    ],
    districtGeometry: mockDistricts[3],
  },
];

export const mockRepFeed: RepFeed = {
  state: "WA",
  updatedAt: "2026-03-14T18:15:00.000Z",
  source: "Congress API mock · symbolic vote alignment feed",
  reps: mockReps,
};

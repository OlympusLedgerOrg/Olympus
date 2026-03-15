export type GeoPoint = {
  lat: number;
  lon: number;
};

export type MapPoint = {
  x: number;
  y: number;
};

export type DistrictGeometry = {
  id: string;
  name: string;
  polygon: GeoPoint[];
  labelPosition?: GeoPoint;
};

export type GeoBounds = {
  minLat: number;
  maxLat: number;
  minLon: number;
  maxLon: number;
};

export const PARTY_COLORS = {
  D: "#00ff41",
  R: "#ff0055",
  I: "#38bdf8",
} as const;

export function getPartyColor(party: string): string {
  return PARTY_COLORS[party as keyof typeof PARTY_COLORS] ?? "#94a3b8";
}

export function getDistrictBounds(districts: DistrictGeometry[]): GeoBounds | null {
  if (districts.length === 0) {
    return null;
  }

  return districts.reduce<GeoBounds>(
    (bounds, district) => {
      district.polygon.forEach((point) => {
        bounds.minLat = Math.min(bounds.minLat, point.lat);
        bounds.maxLat = Math.max(bounds.maxLat, point.lat);
        bounds.minLon = Math.min(bounds.minLon, point.lon);
        bounds.maxLon = Math.max(bounds.maxLon, point.lon);
      });
      return bounds;
    },
    {
      minLat: districts[0].polygon[0]?.lat ?? 0,
      maxLat: districts[0].polygon[0]?.lat ?? 0,
      minLon: districts[0].polygon[0]?.lon ?? 0,
      maxLon: districts[0].polygon[0]?.lon ?? 0,
    },
  );
}

export function projectPoint(
  point: GeoPoint,
  bounds: GeoBounds,
  width: number,
  height: number,
  padding = 24,
): MapPoint {
  const safeWidth = Math.max(width - padding * 2, 1);
  const safeHeight = Math.max(height - padding * 2, 1);
  const lonSpan = bounds.maxLon - bounds.minLon || 1;
  const latSpan = bounds.maxLat - bounds.minLat || 1;

  return {
    x: padding + ((point.lon - bounds.minLon) / lonSpan) * safeWidth,
    y: padding + ((bounds.maxLat - point.lat) / latSpan) * safeHeight,
  };
}

export function getPolygonCentroid(polygon: GeoPoint[]): GeoPoint {
  if (polygon.length === 0) {
    return { lat: 0, lon: 0 };
  }

  const totals = polygon.reduce(
    (acc, point) => ({
      lat: acc.lat + point.lat,
      lon: acc.lon + point.lon,
    }),
    { lat: 0, lon: 0 },
  );

  return {
    lat: totals.lat / polygon.length,
    lon: totals.lon / polygon.length,
  };
}

export function pointInPolygon(point: MapPoint, polygon: MapPoint[]): boolean {
  if (polygon.length < 3) {
    return false;
  }

  let inside = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const xi = polygon[i].x;
    const yi = polygon[i].y;
    const xj = polygon[j].x;
    const yj = polygon[j].y;
    const intersect =
      yi > point.y !== yj > point.y &&
      point.x < ((xj - xi) * (point.y - yi)) / ((yj - yi) || 1e-9) + xi;
    if (intersect) {
      inside = !inside;
    }
  }
  return inside;
}

export function findDistrictForPoint(
  point: GeoPoint,
  districts: DistrictGeometry[],
): DistrictGeometry | null {
  const target = districts.find((district) => {
    const polygon = district.polygon.map((node) => ({
      x: node.lon,
      y: node.lat,
    }));
    return pointInPolygon({ x: point.lon, y: point.lat }, polygon);
  });

  return target ?? null;
}

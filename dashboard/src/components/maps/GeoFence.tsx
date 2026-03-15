import type { RepresentativeProfile } from "@/lib/mocks/reps";
import type { LocationResult } from "@/lib/hooks/useLocation";
import type { DistrictGeometry } from "@/lib/utils/districtMath";

const statusCopy: Record<LocationResult["status"], string> = {
  idle: "Awaiting location permission.",
  locating: "Searching for device location.",
  ready: "Location locked for geofence checks.",
  denied: "Location permission denied; using fallback.",
};

export function GeoFence({
  location,
  district,
  rep,
}: {
  location: LocationResult;
  district: DistrictGeometry | null;
  rep: RepresentativeProfile | null;
}) {
  return (
    <section
      className="border p-5"
      style={{
        background: "var(--color-surface)",
        borderColor: "var(--color-border)",
        borderRadius: "var(--radius)",
      }}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs uppercase tracking-[0.3em]" style={{ color: "var(--color-text-muted)" }}>
            Geofence
          </p>
          <h3 className="mt-2 text-lg font-semibold" style={{ color: "var(--color-primary)" }}>
            District lock · {district ? district.name : "Outside coverage"}
          </h3>
          <p className="mt-2 text-sm" style={{ color: "var(--color-text-muted)" }}>
            {statusCopy[location.status]} Source: {location.source}.
          </p>
        </div>
        <div className="text-xs" style={{ color: "var(--color-text-muted)" }}>
          Updated {new Date(location.updatedAt).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}
        </div>
      </div>

      <div className="mt-4 grid gap-4 sm:grid-cols-2">
        <div
          className="border p-4"
          style={{
            background: "var(--color-surface-muted)",
            borderColor: "var(--color-border)",
            borderRadius: "var(--radius)",
          }}
        >
          <p className="text-xs uppercase tracking-[0.2em]" style={{ color: "var(--color-text-muted)" }}>
            Coordinates
          </p>
          <p className="mt-2 text-sm" style={{ color: "var(--color-text)" }}>
            {location.location.lat.toFixed(3)}, {location.location.lon.toFixed(3)}
          </p>
          {location.error ? (
            <p className="mt-2 text-xs" style={{ color: "var(--color-danger)" }}>
              {location.error}
            </p>
          ) : null}
        </div>
        <div
          className="border p-4"
          style={{
            background: "var(--color-surface-muted)",
            borderColor: "var(--color-border)",
            borderRadius: "var(--radius)",
          }}
        >
          <p className="text-xs uppercase tracking-[0.2em]" style={{ color: "var(--color-text-muted)" }}>
            Active representative
          </p>
          <p className="mt-2 text-sm" style={{ color: "var(--color-text)" }}>
            {rep ? `${rep.name} · ${rep.district}` : "No match"}
          </p>
          <p className="mt-2 text-xs" style={{ color: "var(--color-text-muted)" }}>
            {rep ? rep.districtName : "Location outside configured districts."}
          </p>
        </div>
      </div>
    </section>
  );
}

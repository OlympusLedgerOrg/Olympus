import type { RepresentativeProfile } from "@/lib/mocks/reps";
import { formatPercent } from "@/lib/utils/formatting";
import { getPartyColor } from "@/lib/utils/districtMath";

export function RepList({
  reps,
  selectedRepId,
  userDistrictId,
  onSelect,
}: {
  reps: RepresentativeProfile[];
  selectedRepId: string | null;
  userDistrictId: string | null;
  onSelect: (repId: string) => void;
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
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-xs uppercase tracking-[0.3em]" style={{ color: "var(--color-text-muted)" }}>
            Representatives
          </p>
          <h3 className="mt-2 text-lg font-semibold" style={{ color: "var(--color-primary)" }}>
            State delegation
          </h3>
        </div>
        <p className="text-xs" style={{ color: "var(--color-text-muted)" }}>
          {reps.length} districts
        </p>
      </div>

      <div className="mt-4 space-y-3">
        {reps.map((rep) => {
          const isSelected = rep.id === selectedRepId;
          const isUserDistrict = rep.districtGeometry.id === userDistrictId;

          return (
            <button
              key={rep.id}
              type="button"
              onClick={() => onSelect(rep.id)}
              className="w-full border p-4 text-left"
              style={{
                background: isSelected
                  ? "var(--color-surface-muted)"
                  : "var(--color-background)",
                borderColor: isSelected ? getPartyColor(rep.party) : "var(--color-border)",
                borderRadius: "var(--radius)",
              }}
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="flex flex-wrap items-center gap-2 text-xs uppercase tracking-[0.2em]">
                    <span style={{ color: getPartyColor(rep.party) }}>{rep.party}</span>
                    <span style={{ color: "var(--color-text-muted)" }}>{rep.district}</span>
                    {isUserDistrict ? (
                      <span style={{ color: "var(--color-primary)" }}>User district</span>
                    ) : null}
                  </div>
                  <p className="mt-2 text-base font-semibold" style={{ color: "var(--color-text)" }}>
                    {rep.name}
                  </p>
                  <p className="mt-1 text-sm" style={{ color: "var(--color-text-muted)" }}>
                    {rep.districtName}
                  </p>
                </div>
                <div className="text-right text-xs" style={{ color: "var(--color-text-muted)" }}>
                  <p>Alignment {formatPercent(rep.alignmentScore)}</p>
                  <p>Attendance {formatPercent(rep.attendance)}</p>
                </div>
              </div>
            </button>
          );
        })}
      </div>
    </section>
  );
}

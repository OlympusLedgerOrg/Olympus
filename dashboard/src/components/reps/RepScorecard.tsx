import type { RepresentativeProfile } from "@/lib/mocks/reps";
import { formatPercent } from "@/lib/utils/formatting";
import { getPartyColor } from "@/lib/utils/districtMath";
import { VoteAlignment } from "@/components/reps/VoteAlignment";

const dateFormatter = new Intl.DateTimeFormat("en-US", {
  month: "short",
  day: "numeric",
  hour: "numeric",
  minute: "2-digit",
});

export function RepScorecard({ rep }: { rep: RepresentativeProfile | null }) {
  if (!rep) {
    return (
      <section
        className="border p-5"
        style={{
          background: "var(--color-surface)",
          borderColor: "var(--color-border)",
          borderRadius: "var(--radius)",
        }}
      >
        <p className="text-sm" style={{ color: "var(--color-text-muted)" }}>
          Select a district to view representative scorecards, attendance monitoring, and vote
          alignment summaries.
        </p>
      </section>
    );
  }

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
            Representative scorecard
          </p>
          <h3 className="mt-2 text-2xl font-semibold" style={{ color: "var(--color-primary)" }}>
            {rep.name}
          </h3>
          <p className="mt-1 text-sm" style={{ color: "var(--color-text-muted)" }}>
            {rep.district} · {rep.districtName}
          </p>
        </div>
        <div className="text-right text-xs" style={{ color: "var(--color-text-muted)" }}>
          <p style={{ color: getPartyColor(rep.party) }}>Party {rep.party}</p>
          <p>Next election {new Date(rep.nextElection).toLocaleDateString("en-US")}</p>
        </div>
      </div>

      <div className="mt-5 grid gap-4 lg:grid-cols-2">
        <div
          className="border p-4"
          style={{
            background: "var(--color-surface-muted)",
            borderColor: "var(--color-border)",
            borderRadius: "var(--radius)",
          }}
        >
          <p className="text-xs uppercase tracking-[0.2em]" style={{ color: "var(--color-text-muted)" }}>
            Alignment + attendance
          </p>
          <div className="mt-3 grid gap-3 text-sm" style={{ color: "var(--color-text)" }}>
            <div className="flex items-center justify-between">
              <span>Symbolic alignment</span>
              <span style={{ color: "var(--color-primary)" }}>{formatPercent(rep.alignmentScore)}</span>
            </div>
            <div className="flex items-center justify-between">
              <span>Attendance monitoring</span>
              <span>{formatPercent(rep.attendance)}</span>
            </div>
          </div>
          <div className="mt-4">
            <VoteAlignment alignment={rep.voteAlignment} score={rep.alignmentScore} />
          </div>
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
            Contact desk
          </p>
          <div className="mt-3 space-y-2 text-sm">
            <p style={{ color: "var(--color-text)" }}>{rep.contact.office}</p>
            <p>
              <a
                href={`tel:${rep.contact.phone}`}
                className="underline"
                style={{ color: "var(--color-primary)" }}
              >
                {rep.contact.phone}
              </a>
            </p>
            <p>
              <a
                href={`mailto:${rep.contact.email}`}
                className="underline"
                style={{ color: "var(--color-primary)" }}
              >
                {rep.contact.email}
              </a>
            </p>
            <p>
              <a
                href={rep.contact.website}
                className="underline"
                style={{ color: "var(--color-primary)" }}
                target="_blank"
                rel="noreferrer"
              >
                {rep.contact.website.replace("https://", "")}
              </a>
            </p>
          </div>
        </div>
      </div>

      <div className="mt-5">
        <p className="text-xs uppercase tracking-[0.2em]" style={{ color: "var(--color-text-muted)" }}>
          Town hall tracking
        </p>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          {rep.townHalls.map((event) => (
            <div
              key={event.id}
              className="border p-3"
              style={{
                background: "var(--color-surface-muted)",
                borderColor: "var(--color-border)",
                borderRadius: "var(--radius)",
              }}
            >
              <div className="flex items-center justify-between text-xs" style={{ color: "var(--color-text-muted)" }}>
                <span>{event.format}</span>
                <span>{event.status.replace("-", " ")}</span>
              </div>
              <p className="mt-2 text-sm font-semibold" style={{ color: "var(--color-text)" }}>
                {event.topic}
              </p>
              <p className="mt-1 text-xs" style={{ color: "var(--color-text-muted)" }}>
                {dateFormatter.format(new Date(event.date))}
              </p>
              <p className="mt-1 text-xs" style={{ color: "var(--color-text-muted)" }}>
                {event.location}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

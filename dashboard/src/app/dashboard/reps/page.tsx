"use client";

import { useEffect, useMemo } from "react";
import { DistrictMap } from "@/components/maps/DistrictMap";
import { GeoFence } from "@/components/maps/GeoFence";
import { RepList } from "@/components/reps/RepList";
import { RepScorecard } from "@/components/reps/RepScorecard";
import { useLocation } from "@/lib/hooks/useLocation";
import { useReps } from "@/lib/hooks/useReps";
import { findDistrictForPoint } from "@/lib/utils/districtMath";

export default function RepresentativeDashboardPage() {
  const { reps, selectedRep, selectedRepId, setSelectedRepId, status, error, metadata } = useReps();
  const location = useLocation();

  const districts = useMemo(() => reps.map((rep) => rep.districtGeometry), [reps]);
  const userDistrict = useMemo(() => {
    if (!location.location) {
      return null;
    }
    return findDistrictForPoint(location.location, districts);
  }, [districts, location.location]);
  const userRep = useMemo(
    () =>
      userDistrict
        ? reps.find((rep) => rep.districtGeometry.id === userDistrict.id) ?? null
        : null,
    [reps, userDistrict],
  );

  useEffect(() => {
    if (!selectedRepId && userRep) {
      setSelectedRepId(userRep.id);
    }
  }, [selectedRepId, setSelectedRepId, userRep]);

  const activeRep = selectedRep ?? userRep ?? null;

  return (
    <main className="flex min-h-screen flex-col items-center px-4 py-8 sm:px-6 sm:py-12">
      <div className="w-full max-w-7xl space-y-6">
        <header className="space-y-4">
          <h1
            className="text-3xl font-bold tracking-tight sm:text-4xl"
            style={{ color: "var(--color-primary)", fontFamily: "var(--font-mono)" }}
          >
            Representative Tracking
          </h1>
          <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <p className="max-w-2xl" style={{ color: "var(--color-text-muted)" }}>
              Monitor district boundaries, geofence your location, and inspect vote alignment
              scorecards for the {metadata.state} delegation. Data feed: {metadata.source}.
            </p>
            <div className="text-sm" style={{ color: "var(--color-text-muted)" }}>
              Updated {new Date(metadata.updatedAt).toLocaleString("en-US")} ·{" "}
              {status === "loading" ? "Syncing feed" : "Feed online"}
            </div>
          </div>
          {error ? (
            <div className="text-sm" style={{ color: "var(--color-danger)" }}>
              {error}
            </div>
          ) : null}
        </header>

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
          <div className="space-y-6 xl:col-span-7">
            <DistrictMap
              reps={reps}
              selectedRepId={selectedRepId}
              userLocation={location.location}
              userDistrictId={userDistrict?.id ?? null}
              onSelectRep={setSelectedRepId}
            />
            <GeoFence location={location} district={userDistrict} rep={userRep} />
          </div>
          <div className="space-y-6 xl:col-span-5">
            <RepScorecard rep={activeRep} />
            <RepList
              reps={reps}
              selectedRepId={selectedRepId}
              userDistrictId={userDistrict?.id ?? null}
              onSelect={setSelectedRepId}
            />
          </div>
        </div>
      </div>
    </main>
  );
}

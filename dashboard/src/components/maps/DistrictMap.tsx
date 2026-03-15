"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { RepresentativeProfile } from "@/lib/mocks/reps";
import {
  getDistrictBounds,
  getPartyColor,
  getPolygonCentroid,
  pointInPolygon,
  projectPoint,
  type MapPoint,
} from "@/lib/utils/districtMath";

type DistrictMapProps = {
  reps: RepresentativeProfile[];
  selectedRepId: string | null;
  userLocation?: { lat: number; lon: number } | null;
  userDistrictId?: string | null;
  onSelectRep?: (repId: string) => void;
};

type ProjectedDistrict = {
  rep: RepresentativeProfile;
  polygon: MapPoint[];
  label: MapPoint;
};

export function DistrictMap({
  reps,
  selectedRepId,
  userLocation,
  userDistrictId,
  onSelectRep,
}: DistrictMapProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [canvasSize, setCanvasSize] = useState({ width: 0, height: 0 });

  const bounds = useMemo(
    () => getDistrictBounds(reps.map((rep) => rep.districtGeometry)),
    [reps],
  );

  const projectedDistricts = useMemo<ProjectedDistrict[]>(() => {
    if (!bounds || canvasSize.width === 0) {
      return [];
    }
    return reps.map((rep) => {
      const labelLocation = rep.districtGeometry.labelPosition ?? getPolygonCentroid(rep.districtGeometry.polygon);
      return {
        rep,
        polygon: rep.districtGeometry.polygon.map((point) =>
          projectPoint(point, bounds, canvasSize.width, canvasSize.height),
        ),
        label: projectPoint(labelLocation, bounds, canvasSize.width, canvasSize.height),
      };
    });
  }, [bounds, canvasSize.height, canvasSize.width, reps]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) {
      return;
    }

    const updateSize = () => {
      const parent = canvas.parentElement;
      if (!parent) {
        return;
      }
      const width = parent.clientWidth;
      const height = Math.max(260, Math.round(width * 0.6));
      setCanvasSize({ width, height });
    };

    updateSize();
    window.addEventListener("resize", updateSize);

    return () => {
      window.removeEventListener("resize", updateSize);
    };
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !bounds || canvasSize.width === 0) {
      return;
    }
    const ctx = canvas.getContext("2d");
    if (!ctx) {
      return;
    }

    const scale = window.devicePixelRatio ?? 1;
    canvas.width = canvasSize.width * scale;
    canvas.height = canvasSize.height * scale;
    canvas.style.width = `${canvasSize.width}px`;
    canvas.style.height = `${canvasSize.height}px`;
    ctx.setTransform(scale, 0, 0, scale, 0, 0);

    const rootStyles = window.getComputedStyle(document.documentElement);
    const borderColor = rootStyles.getPropertyValue("--color-border").trim() || "#1f2937";
    const surfaceColor =
      rootStyles.getPropertyValue("--color-surface-muted").trim() || "#0b0b0b";
    const textColor = rootStyles.getPropertyValue("--color-text").trim() || "#e5e7eb";
    const accentColor = rootStyles.getPropertyValue("--color-primary").trim() || "#00ff41";

    ctx.clearRect(0, 0, canvasSize.width, canvasSize.height);
    ctx.fillStyle = surfaceColor;
    ctx.fillRect(0, 0, canvasSize.width, canvasSize.height);

    projectedDistricts.forEach((district) => {
      const isSelected = district.rep.id === selectedRepId;
      const isUserDistrict = district.rep.districtGeometry.id === userDistrictId;
      const partyColor = getPartyColor(district.rep.party);

      ctx.beginPath();
      district.polygon.forEach((point, index) => {
        if (index === 0) {
          ctx.moveTo(point.x, point.y);
        } else {
          ctx.lineTo(point.x, point.y);
        }
      });
      ctx.closePath();
      ctx.fillStyle = partyColor;
      ctx.globalAlpha = isSelected ? 0.28 : 0.14;
      ctx.fill();
      ctx.globalAlpha = 1;
      ctx.lineWidth = isSelected ? 2.6 : 1.2;
      ctx.strokeStyle = isSelected ? partyColor : borderColor;
      ctx.stroke();

      if (isUserDistrict) {
        ctx.save();
        ctx.setLineDash([6, 4]);
        ctx.lineWidth = 2;
        ctx.strokeStyle = accentColor;
        ctx.stroke();
        ctx.restore();
      }

      ctx.fillStyle = textColor;
      ctx.font = "12px var(--font-mono, ui-monospace)";
      ctx.textAlign = "center";
      ctx.fillText(district.rep.district, district.label.x, district.label.y);
    });

    if (userLocation) {
      const userPoint = projectPoint(userLocation, bounds, canvasSize.width, canvasSize.height);
      ctx.beginPath();
      ctx.arc(userPoint.x, userPoint.y, 5, 0, Math.PI * 2);
      ctx.fillStyle = accentColor;
      ctx.fill();
      ctx.strokeStyle = surfaceColor;
      ctx.lineWidth = 1;
      ctx.stroke();
    }
  }, [bounds, canvasSize.height, canvasSize.width, projectedDistricts, selectedRepId, userDistrictId, userLocation]);

  const handleClick = (event: React.MouseEvent<HTMLCanvasElement>) => {
    if (!onSelectRep || projectedDistricts.length === 0) {
      return;
    }
    const canvas = canvasRef.current;
    if (!canvas) {
      return;
    }
    const rect = canvas.getBoundingClientRect();
    const point = { x: event.clientX - rect.left, y: event.clientY - rect.top };
    const hit = projectedDistricts.find((district) =>
      pointInPolygon(point, district.polygon),
    );
    if (hit) {
      onSelectRep(hit.rep.id);
    }
  };

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
            District map
          </p>
          <h2 className="mt-2 text-xl font-semibold" style={{ color: "var(--color-primary)" }}>
            Interactive geofenced grid
          </h2>
          <p className="mt-2 text-sm" style={{ color: "var(--color-text-muted)" }}>
            Click a district to inspect the representative scorecard and symbolic vote alignment.
          </p>
        </div>
        <div className="text-xs" style={{ color: "var(--color-text-muted)" }}>
          Canvas render · simplified boundaries
        </div>
      </div>
      <div
        className="mt-4 overflow-hidden border"
        style={{ borderColor: "var(--color-border)", borderRadius: "var(--radius)" }}
      >
        <canvas
          ref={canvasRef}
          className="h-full w-full cursor-pointer"
          role="img"
          aria-label="District map showing representatives by party and geofence highlight"
          onClick={handleClick}
        />
      </div>
      <div className="mt-4 flex flex-wrap items-center gap-4 text-xs" style={{ color: "var(--color-text-muted)" }}>
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full" style={{ background: getPartyColor("D") }} />
          Democrat
        </div>
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full" style={{ background: getPartyColor("R") }} />
          Republican
        </div>
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full" style={{ background: "var(--color-primary)" }} />
          User location
        </div>
      </div>
    </section>
  );
}

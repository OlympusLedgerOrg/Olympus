"use client";

import { useEffect, useState } from "react";
import { mockUserLocation } from "@/lib/mocks/reps";
import type { GeoPoint } from "@/lib/utils/districtMath";

export type LocationStatus = "idle" | "locating" | "ready" | "denied";
export type LocationSource = "device" | "fallback";

export type LocationResult = {
  location: GeoPoint;
  status: LocationStatus;
  source: LocationSource;
  updatedAt: string;
  error?: string;
};

const DEFAULT_UPDATED_AT = new Date().toISOString();

export function useLocation(): LocationResult {
  const [location, setLocation] = useState<GeoPoint>(mockUserLocation);
  const [status, setStatus] = useState<LocationStatus>("idle");
  const [source, setSource] = useState<LocationSource>("fallback");
  const [updatedAt, setUpdatedAt] = useState<string>(DEFAULT_UPDATED_AT);
  const [error, setError] = useState<string | undefined>(undefined);

  useEffect(() => {
    if (typeof window === "undefined") {
      setStatus("ready");
      return;
    }
    if (!navigator.geolocation) {
      setStatus("ready");
      return;
    }

    setStatus("locating");
    navigator.geolocation.getCurrentPosition(
      (position) => {
        setLocation({
          lat: position.coords.latitude,
          lon: position.coords.longitude,
        });
        setSource("device");
        setStatus("ready");
        setError(undefined);
        setUpdatedAt(new Date().toISOString());
      },
      (geoError) => {
        setStatus("denied");
        setSource("fallback");
        setError(geoError.message);
        setUpdatedAt(new Date().toISOString());
      },
      { enableHighAccuracy: false, maximumAge: 300000, timeout: 8000 },
    );
  }, []);

  return { location, status, source, updatedAt, error };
}

import { NextResponse } from "next/server";
import { mockRepFeed } from "@/lib/mocks/reps";

export async function GET() {
  return NextResponse.json(mockRepFeed, { status: 200 });
}

import { NextResponse } from "next/server";
import { mockBillFeed } from "@/lib/mocks/bills";

export async function GET() {
  return NextResponse.json(mockBillFeed, { status: 200 });
}

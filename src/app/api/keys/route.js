import { NextResponse } from "next/server";
import { getApiKeys, createApiKey } from "@/lib/localDb";
import { getConsistentMachineId } from "@/shared/utils/machineId";

export const dynamic = "force-dynamic";

// GET /api/keys - List API keys
export async function GET() {
  try {
    const keys = await getApiKeys();
    return NextResponse.json({ keys });
  } catch (error) {
    console.log("Error fetching keys:", error);
    return NextResponse.json({ error: "Failed to fetch keys" }, { status: 500 });
  }
}

// POST /api/keys - Create new API key
export async function POST(request) {
  try {
    const body = await request.json();
    const { name, customKey, prefix, expiresAt, quotaLimit, notes, access, useMachineId } = body;

    if (!name || !name.trim()) {
      return NextResponse.json({ error: "Name is required" }, { status: 400 });
    }

    // Get machineId from server
    let machineId = null;
    try {
      machineId = await getConsistentMachineId();
    } catch {}

    const apiKey = await createApiKey(name.trim(), machineId, {
      customKey,
      prefix,
      expiresAt,
      quotaLimit,
      notes,
      access,
      useMachineId: !!useMachineId,
    });

    return NextResponse.json({
      ...apiKey,
    }, { status: 201 });
  } catch (error) {
    console.log("Error creating key:", error);
    return NextResponse.json({ error: error.message || "Failed to create key" }, { status: 500 });
  }
}

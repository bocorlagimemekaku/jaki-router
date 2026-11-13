import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";
import { getAdapter } from "../driver.js";
import { keyAccessFromColumns, keyAccessToColumns } from "@/shared/utils/keyAccess.js";
import { KEY_ACCESS_UNRESTRICTED } from "@/shared/constants/keyAccess.js";

function rowToKey(row) {
  if (!row) return null;
  return {
    id: row.id,
    key: row.key,
    name: row.name,
    machineId: row.machineId,
    isActive: row.isActive === 1 || row.isActive === true,
    createdAt: row.createdAt,
    access: keyAccessFromColumns(row.accessRestricted, row.accessAllow),
    expiresAt: row.expiresAt || null,
    quotaLimit: row.quotaLimit !== undefined && row.quotaLimit !== null ? Number(row.quotaLimit) : 0,
    notes: row.notes || "",
    usedCost: row.usedCost !== undefined ? Number(row.usedCost) : 0,
    usedRequests: row.usedRequests !== undefined ? Number(row.usedRequests) : 0,
  };
}

export async function getApiKeys() {
  const db = await getAdapter();
  try {
    const rows = db.all(`
      SELECT a.*, 
        COALESCE(u.totalCost, 0) as usedCost,
        COALESCE(u.totalRequests, 0) as usedRequests
      FROM apiKeys a
      LEFT JOIN (
        SELECT apiKey, SUM(cost) as totalCost, COUNT(*) as totalRequests
        FROM usageHistory
        WHERE apiKey IS NOT NULL AND apiKey != ''
        GROUP BY apiKey
      ) u ON a.key = u.apiKey
      ORDER BY a.createdAt DESC
    `);
    return rows.map(rowToKey);
  } catch {
    const rows = db.all(`SELECT * FROM apiKeys ORDER BY createdAt DESC`);
    return rows.map(rowToKey);
  }
}

export async function getApiKeyById(id) {
  const db = await getAdapter();
  try {
    const row = db.get(`
      SELECT a.*, 
        COALESCE(u.totalCost, 0) as usedCost,
        COALESCE(u.totalRequests, 0) as usedRequests
      FROM apiKeys a
      LEFT JOIN (
        SELECT apiKey, SUM(cost) as totalCost, COUNT(*) as totalRequests
        FROM usageHistory
        WHERE apiKey IS NOT NULL AND apiKey != ''
        GROUP BY apiKey
      ) u ON a.key = u.apiKey
      WHERE a.id = ?
    `, [id]);
    return rowToKey(row);
  } catch {
    const row = db.get(`SELECT * FROM apiKeys WHERE id = ?`, [id]);
    return rowToKey(row);
  }
}

// Used by the /v1 handlers to read the presented key's access settings.
export async function getApiKeyByKey(key) {
  if (!key) return null;
  const db = await getAdapter();
  try {
    const row = db.get(`
      SELECT a.*, 
        COALESCE(u.totalCost, 0) as usedCost,
        COALESCE(u.totalRequests, 0) as usedRequests
      FROM apiKeys a
      LEFT JOIN (
        SELECT apiKey, SUM(cost) as totalCost, COUNT(*) as totalRequests
        FROM usageHistory
        WHERE apiKey IS NOT NULL AND apiKey != ''
        GROUP BY apiKey
      ) u ON a.key = u.apiKey
      WHERE a.key = ?
    `, [key]);
    return rowToKey(row);
  } catch {
    const row = db.get(`SELECT * FROM apiKeys WHERE key = ?`, [key]);
    return rowToKey(row);
  }
}

export async function getApiKeyUsageCost(key) {
  if (!key) return 0;
  const db = await getAdapter();
  try {
    const row = db.get(`SELECT COALESCE(SUM(cost), 0) as totalCost FROM usageHistory WHERE apiKey = ?`, [key]);
    return Number(row?.totalCost || 0);
  } catch {
    return 0;
  }
}

export async function createApiKey(name, machineId, options = {}) {
  const db = await getAdapter();
  let keyString = options.customKey?.trim();

  if (!keyString) {
    if (options.useMachineId && machineId) {
      const { generateApiKeyWithMachine } = await import("@/shared/utils/apiKey");
      keyString = generateApiKeyWithMachine(machineId).key;
    } else {
      const prefix = options.prefix || "sk-jaki-";
      const randomPart = crypto.randomBytes(16).toString("hex");
      keyString = `${prefix}${randomPart}`;
    }
  }

  // Check key uniqueness
  const existing = db.get(`SELECT id FROM apiKeys WHERE key = ?`, [keyString]);
  if (existing) {
    throw new Error("API key already exists");
  }

  const access = options.access || KEY_ACCESS_UNRESTRICTED;
  const cols = keyAccessToColumns(access);

  const apiKey = {
    id: uuidv4(),
    name: name || "Jaki Key",
    key: keyString,
    machineId: machineId || "jaki-server",
    isActive: options.isActive !== undefined ? (options.isActive ? 1 : 0) : 1,
    createdAt: new Date().toISOString(),
    accessRestricted: cols.accessRestricted,
    accessAllow: cols.accessAllow,
    expiresAt: options.expiresAt ? new Date(options.expiresAt).toISOString() : null,
    quotaLimit: options.quotaLimit !== undefined && options.quotaLimit !== null ? Math.max(0, Number(options.quotaLimit)) : 0,
    notes: options.notes ? String(options.notes).trim() : "",
  };

  db.run(
    `INSERT INTO apiKeys(id, key, name, machineId, isActive, createdAt, accessRestricted, accessAllow, expiresAt, quotaLimit, notes) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      apiKey.id,
      apiKey.key,
      apiKey.name,
      apiKey.machineId,
      apiKey.isActive,
      apiKey.createdAt,
      apiKey.accessRestricted,
      apiKey.accessAllow,
      apiKey.expiresAt,
      apiKey.quotaLimit,
      apiKey.notes,
    ]
  );
  return rowToKey(apiKey);
}

export async function updateApiKey(id, data) {
  const db = await getAdapter();
  let result = null;
  db.transaction(() => {
    const row = db.get(`SELECT * FROM apiKeys WHERE id = ?`, [id]);
    if (!row) return;
    const current = rowToKey(row);
    const merged = { ...current, ...data };
    const cols = keyAccessToColumns(merged.access);

    // If key string changed, check uniqueness
    if (data.key && data.key !== current.key) {
      const dup = db.get(`SELECT id FROM apiKeys WHERE key = ? AND id != ?`, [data.key, id]);
      if (dup) throw new Error("API key already exists");
    }

    const expiresAt = merged.expiresAt ? new Date(merged.expiresAt).toISOString() : null;
    const quotaLimit = merged.quotaLimit !== undefined && merged.quotaLimit !== null ? Math.max(0, Number(merged.quotaLimit)) : 0;
    const notes = merged.notes !== undefined ? String(merged.notes) : (current.notes || "");

    db.run(
      `UPDATE apiKeys SET key = ?, name = ?, machineId = ?, isActive = ?, accessRestricted = ?, accessAllow = ?, expiresAt = ?, quotaLimit = ?, notes = ? WHERE id = ?`,
      [
        merged.key,
        merged.name,
        merged.machineId,
        merged.isActive ? 1 : 0,
        cols.accessRestricted,
        cols.accessAllow,
        expiresAt,
        quotaLimit,
        notes,
        id
      ]
    );
    result = rowToKey(db.get(`SELECT * FROM apiKeys WHERE id = ?`, [id]));
  });
  return result;
}

export async function deleteApiKey(id) {
  const db = await getAdapter();
  const res = db.run(`DELETE FROM apiKeys WHERE id = ?`, [id]);
  return (res?.changes ?? 0) > 0;
}

export async function validateApiKeyDetailed(key) {
  if (!key) return { valid: false, error: "Missing API key", code: 401 };
  const db = await getAdapter();
  const row = db.get(`SELECT * FROM apiKeys WHERE key = ?`, [key]);
  if (!row) return { valid: false, error: "Invalid API key", code: 401 };
  if (row.isActive !== 1 && row.isActive !== true) {
    return { valid: false, error: "API key is paused/inactive", code: 401 };
  }

  // Check expiration
  if (row.expiresAt) {
    const exp = new Date(row.expiresAt).getTime();
    if (!isNaN(exp) && Date.now() > exp) {
      return {
        valid: false,
        error: `API key expired on ${new Date(row.expiresAt).toLocaleDateString()}. Please renew with Jaki.`,
        code: 401,
      };
    }
  }

  // Check quota limit
  if (row.quotaLimit && Number(row.quotaLimit) > 0) {
    const limit = Number(row.quotaLimit);
    try {
      const usageRow = db.get(`SELECT COALESCE(SUM(cost), 0) as totalCost FROM usageHistory WHERE apiKey = ?`, [key]);
      const totalCost = Number(usageRow?.totalCost || 0);
      if (totalCost >= limit) {
        return {
          valid: false,
          error: `API key quota limit reached ($${totalCost.toFixed(2)} / $${limit.toFixed(2)}). Please contact Jaki to top up.`,
          code: 429,
        };
      }
    } catch {}
  }

  return { valid: true, key: rowToKey(row) };
}

export async function validateApiKey(key) {
  const result = await validateApiKeyDetailed(key);
  return result.valid;
}

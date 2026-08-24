import { getStore } from "@netlify/blobs";
import { createHash, createHmac, randomBytes, randomInt, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";

const STORE_NAME = "taxi-turicato";
const DATABASE_KEY = "central-operativa-v1";
const COOKIE_NAME = "taxi_turicato";
const SESSION_SECONDS = 60 * 60 * 24 * 7;
const ACTIVE_RIDES = new Set(["requested", "accepted", "arrived", "in_progress"]);
const COLORS = new Set(["#134738", "#537dd5", "#d58237", "#9556a1", "#bd4f5a", "#438e80"]);

const DEFAULT_SETTINGS = {
  base_fare: 35,
  fare_per_km: 11,
  minimum_fare: 45,
  service_enabled: true,
  support_phone: "",
  service_area: "Turicato, Michoacán",
};

class AppError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

function response(payload, status = 200, extraHeaders = {}) {
  return Response.json(payload, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders,
    },
  });
}

function value(input, length = 160) {
  return typeof input === "string" ? input.trim().slice(0, length) : "";
}

function number(input, fallback = 0) {
  const parsed = typeof input === "number" ? input : Number(input);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function date() {
  return new Date().toISOString();
}

function email(input) {
  return value(input, 120).toLowerCase();
}

function validEmail(input) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);
}

function requireConfiguration() {
  const administrator = email(process.env.TAXI_ADMIN_EMAIL);
  const password = process.env.TAXI_ADMIN_PASSWORD || "";
  const secret = process.env.TAXI_SESSION_SECRET || "";

  if (!validEmail(administrator) || password.length < 12 || secret.length < 32) {
    throw new AppError(
      "La administración debe configurar TAXI_ADMIN_EMAIL, TAXI_ADMIN_PASSWORD y TAXI_SESSION_SECRET en Netlify.",
      503,
    );
  }

  return { administrator, password, secret };
}

function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, 64).toString("hex");
  return `scrypt$${salt}$${hash}`;
}

function verifyPassword(password, encoded) {
  const [algorithm, salt, known] = String(encoded || "").split("$");
  if (algorithm !== "scrypt" || !salt || !known) return false;
  const actual = scryptSync(password, salt, 64);
  const expected = Buffer.from(known, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function tokenFor(account, secret) {
  const content = Buffer.from(JSON.stringify({
    id: account.id,
    email: account.email,
    expires: Date.now() + SESSION_SECONDS * 1000,
  }), "utf8").toString("base64url");
  const signature = createHmac("sha256", secret).update(content).digest("base64url");
  return `${content}.${signature}`;
}

function parseSession(request, secret) {
  const rawCookie = request.headers.get("cookie") || "";
  const match = rawCookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${COOKIE_NAME}=`));
  if (!match) return null;

  const token = match.slice(COOKIE_NAME.length + 1);
  const [content, signature, unexpected] = token.split(".");
  if (!content || !signature || unexpected) return null;

  const expected = createHmac("sha256", secret).update(content).digest("base64url");
  const knownBytes = Buffer.from(signature);
  const expectedBytes = Buffer.from(expected);
  if (knownBytes.length !== expectedBytes.length || !timingSafeEqual(knownBytes, expectedBytes)) return null;

  try {
    const payload = JSON.parse(Buffer.from(content, "base64url").toString("utf8"));
    return typeof payload.expires === "number" && payload.expires > Date.now() ? payload : null;
  } catch {
    return null;
  }
}

function cookie(request, token, expiration = SESSION_SECONDS) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${expiration}${secure}`;
}

function emptyDatabase() {
  return {
    version: 1,
    users: [],
    unions: [],
    groups: [],
    drivers: [],
    rides: [],
    activity: [],
    login_attempts: {},
    settings: { ...DEFAULT_SETTINGS },
  };
}

function blobStore() {
  return getStore({ name: STORE_NAME, consistency: "strong" });
}

async function snapshot() {
  const entry = await blobStore().getWithMetadata(DATABASE_KEY, { type: "json", consistency: "strong" });
  if (!entry) return { data: emptyDatabase(), etag: null };
  return { data: entry.data, etag: entry.etag };
}

async function transaction(change) {
  const store = blobStore();
  for (let attempt = 0; attempt < 8; attempt++) {
    const current = await snapshot();
    const next = structuredClone(current.data);
    const result = await change(next);
    const condition = current.etag ? { onlyIfMatch: current.etag } : { onlyIfNew: true };
    const write = await store.setJSON(DATABASE_KEY, next, condition);
    if (write.modified) return { result, data: next };
  }

  throw new AppError("Hay mucha actividad al mismo tiempo. Inténtalo nuevamente.", 409);
}

function record(database, actor, action, description, relatedId = null) {
  database.activity.unshift({
    id: randomUUID(),
    actor_email: actor,
    action,
    description,
    related_id: relatedId,
    created_at: date(),
  });
  database.activity = database.activity.slice(0, 300);
}

async function ensureAdministrator(configuration) {
  const existing = (await snapshot()).data;
  if (existing.users.some((account) => account.role === "admin")) return existing;

  return (await transaction((database) => {
    if (database.users.some((account) => account.role === "admin")) return;
    const admin = {
      id: randomUUID(),
      name: "Administrador Taxi Turicato",
      email: configuration.administrator,
      phone: "",
      role: "admin",
      password_hash: hashPassword(configuration.password),
      active: true,
      created_at: date(),
    };
    database.users.push(admin);
    record(database, admin.email, "admin_created", "Se creó la administración principal.", admin.id);
  })).data;
}

function accountWithoutSecrets(account) {
  if (!account) return null;
  const { password_hash: _passwordHash, ...safe } = account;
  return safe;
}

function driverOrganization(database, driver) {
  const union = database.unions.find((item) => item.id === driver.union_id);
  const group = driver.group_id ? database.groups.find((item) => item.id === driver.group_id) : null;
  return { union, group, operational: Boolean(union?.active && (!driver.group_id || group?.active)) };
}

function enrichedDriver(database, driver, privateFields = false) {
  const { union, group } = driverOrganization(database, driver);
  const enriched = { ...driver, union_name: union?.name || "", group_name: group?.name || "" };
  if (!privateFields) {
    delete enriched.email;
    delete enriched.phone;
    delete enriched.license_number;
    delete enriched.permit_number;
  }
  return enriched;
}

function enrichedRide(database, ride) {
  const driver = ride.driver_id ? database.drivers.find((item) => item.id === ride.driver_id) : null;
  if (!driver) return { ...ride };
  const { union, group } = driverOrganization(database, driver);
  return {
    ...ride,
    driver_name: driver.name,
    driver_phone: driver.phone,
    driver_unit: driver.unit_number,
    driver_plate: driver.plate,
    driver_vehicle: driver.vehicle,
    driver_vehicle_color: driver.vehicle_color,
    driver_rating: driver.rating,
    union_name: union?.name || "",
    group_name: group?.name || "",
  };
}

function publicOrganization(item) {
  return { id: item.id, name: item.name, color: item.color, active: item.active, parent_id: item.parent_id || null };
}

function visibleState(database, account) {
  const ownDriver = account.role === "driver" ? database.drivers.find((driver) => driver.email === account.email) : null;
  if (account.role === "driver" && (!ownDriver || !ownDriver.active || !ownDriver.verified)) {
    throw new AppError("Tu unidad no está autorizada. Comunícate con administración.", 403);
  }

  let drivers = [];
  let rides = [];

  if (account.role === "admin") {
    drivers = database.drivers.map((driver) => enrichedDriver(database, driver, true));
    rides = database.rides.map((ride) => enrichedRide(database, ride));
  } else if (account.role === "driver") {
    drivers = [enrichedDriver(database, ownDriver, true)];
    rides = database.rides
      .filter((ride) => ride.driver_id === ownDriver.id || ride.status === "requested")
      .map((ride) => {
        const safe = enrichedRide(database, ride);
        delete safe.security_code;
        if (ride.driver_id !== ownDriver.id) safe.passenger_phone = "";
        return safe;
      });
  } else {
    drivers = database.drivers
      .filter((driver) => driver.active && driver.verified && driver.status === "available" && driverOrganization(database, driver).operational)
      .map((driver) => enrichedDriver(database, driver));
    rides = database.rides.filter((ride) => ride.passenger_email === account.email).map((ride) => enrichedRide(database, ride));
  }

  rides.sort((first, second) => {
    const firstActive = ACTIVE_RIDES.has(first.status) ? 0 : 1;
    const secondActive = ACTIVE_RIDES.has(second.status) ? 0 : 1;
    return firstActive - secondActive || Date.parse(second.created_at) - Date.parse(first.created_at);
  });

  return {
    authenticated: true,
    account: accountWithoutSecrets(account),
    ownDriver: ownDriver ? enrichedDriver(database, ownDriver, true) : null,
    unions: account.role === "admin" ? database.unions : database.unions.filter((item) => item.active).map(publicOrganization),
    groups: account.role === "admin" ? database.groups : database.groups.filter((item) => item.active).map(publicOrganization),
    drivers,
    rides: rides.slice(0, 150),
    passengers: account.role === "admin" ? database.users.filter((item) => item.role === "passenger").map(accountWithoutSecrets) : [],
    activity: account.role === "admin" ? database.activity.slice(0, 30) : [],
    settings: database.settings,
  };
}

function signedInAccount(request, database, configuration) {
  const session = parseSession(request, configuration.secret);
  if (!session) return null;
  const account = database.users.find((item) => item.id === session.id && item.email === session.email);
  return account?.active ? account : null;
}

function loginAttemptKey(accountEmail) {
  return createHash("sha256").update(accountEmail).digest("hex").slice(0, 20);
}

function ensureNotLocked(database, accountEmail) {
  const attempts = database.login_attempts[loginAttemptKey(accountEmail)];
  if (attempts?.until && attempts.until > Date.now()) {
    throw new AppError("Demasiados intentos. Espera 15 minutos antes de volver a iniciar sesión.", 429);
  }
}

function organizationOfKind(database, kind) {
  return kind === "group" ? database.groups : database.unions;
}

function requireAdmin(account) {
  if (account.role !== "admin") throw new AppError("Esta acción es exclusiva de administración.", 403);
}

function coordinatesDistance(aLat, aLng, bLat, bLng) {
  const radians = (degrees) => degrees * Math.PI / 180;
  const latitude = radians(bLat - aLat);
  const longitude = radians(bLng - aLng);
  const total = Math.sin(latitude / 2) ** 2 + Math.cos(radians(aLat)) * Math.cos(radians(bLat)) * Math.sin(longitude / 2) ** 2;
  return 6371 * 2 * Math.atan2(Math.sqrt(total), Math.sqrt(1 - total));
}

async function login(request, payload, configuration, database) {
  const accountEmail = email(payload.email);
  const password = String(payload.password || "");
  if (!validEmail(accountEmail) || !password) throw new AppError("Escribe tu correo y tu contraseña.");
  ensureNotLocked(database, accountEmail);

  const account = database.users.find((item) => item.email === accountEmail);
  const valid = account?.active && verifyPassword(password, account.password_hash);
  if (!valid) {
    await transaction((current) => {
      const key = loginAttemptKey(accountEmail);
      const previous = current.login_attempts[key] || { count: 0, until: 0, updated: 0 };
      const expired = previous.updated < Date.now() - 15 * 60 * 1000;
      const count = expired ? 1 : previous.count + 1;
      current.login_attempts[key] = { count, updated: Date.now(), until: count >= 6 ? Date.now() + 15 * 60 * 1000 : 0 };
    });
    throw new AppError("Correo o contraseña incorrectos.", 401);
  }

  const result = await transaction((current) => {
    delete current.login_attempts[loginAttemptKey(accountEmail)];
    const fresh = current.users.find((item) => item.id === account.id);
    record(current, fresh.email, "login", `${fresh.name} inició sesión.`, fresh.id);
    return fresh;
  });

  return response({ ok: true, account: accountWithoutSecrets(result.result) }, 200, {
    "Set-Cookie": cookie(request, tokenFor(result.result, configuration.secret)),
  });
}

async function registerPassenger(request, payload, configuration) {
  const name = value(payload.name, 90);
  const accountEmail = email(payload.email);
  const phone = value(payload.phone, 20).replace(/[^\d+\s()-]/g, "");
  const password = String(payload.password || "");

  if (name.length < 3 || !validEmail(accountEmail) || phone.replace(/\D/g, "").length < 8 || password.length < 8) {
    throw new AppError("Completa nombre, correo, teléfono y una contraseña de al menos 8 caracteres.");
  }
  if (accountEmail === configuration.administrator) throw new AppError("Ese correo está reservado para administración.", 409);

  const saved = await transaction((database) => {
    if (database.users.some((account) => account.email === accountEmail)) {
      throw new AppError("Ya existe una cuenta con ese correo.", 409);
    }
    const account = {
      id: randomUUID(),
      name,
      email: accountEmail,
      phone,
      role: "passenger",
      password_hash: hashPassword(password),
      active: true,
      created_at: date(),
    };
    database.users.push(account);
    record(database, accountEmail, "passenger_created", `Se registró el pasajero ${name}.`, account.id);
    return account;
  });

  return response({ ok: true, account: accountWithoutSecrets(saved.result) }, 201, {
    "Set-Cookie": cookie(request, tokenFor(saved.result, configuration.secret)),
  });
}

function performAction(database, account, action, payload) {
  const currentAccount = database.users.find((item) => item.id === account.id);
  if (!currentAccount?.active) throw new AppError("Tu sesión ya no está disponible.", 401);

  if (action === "saveProfile") {
    const name = value(payload.name, 90);
    const phone = value(payload.phone, 20).replace(/[^\d+\s()-]/g, "");
    if (name.length < 3) throw new AppError("Escribe tu nombre completo.");
    currentAccount.name = name;
    currentAccount.phone = phone;
    if (currentAccount.role === "driver") {
      const driver = database.drivers.find((item) => item.email === currentAccount.email);
      if (driver) { driver.name = name; driver.phone = phone; }
    }
    return;
  }

  if (action === "changePassword") {
    const previous = String(payload.currentPassword || "");
    const next = String(payload.newPassword || "");
    if (!verifyPassword(previous, currentAccount.password_hash)) throw new AppError("La contraseña actual no coincide.", 403);
    if (next.length < 8) throw new AppError("La nueva contraseña debe tener al menos 8 caracteres.");
    currentAccount.password_hash = hashPassword(next);
    record(database, currentAccount.email, "password_changed", "Se actualizó la contraseña de la cuenta.", currentAccount.id);
    return;
  }

  if (action === "createOrganization") {
    requireAdmin(currentAccount);
    const kind = payload.kind === "group" ? "group" : "union";
    const name = value(payload.name, 90);
    const parentId = value(payload.parentId, 64);
    if (name.length < 3) throw new AppError("Escribe el nombre del sindicato o grupo.");
    if (kind === "group" && !database.unions.some((item) => item.id === parentId && item.active)) {
      throw new AppError("El grupo debe pertenecer a un sindicato activo.");
    }
    const target = organizationOfKind(database, kind);
    if (target.some((item) => item.name.toLowerCase() === name.toLowerCase() && (kind === "union" || item.parent_id === parentId))) {
      throw new AppError("Ya existe una organización registrada con ese nombre.", 409);
    }
    const organization = {
      id: randomUUID(), name, kind, parent_id: kind === "group" ? parentId : null,
      color: COLORS.has(value(payload.color, 8)) ? value(payload.color, 8) : "#134738",
      contact_name: value(payload.contactName, 90), phone: value(payload.phone, 20), active: true, created_at: date(),
    };
    target.push(organization);
    record(database, currentAccount.email, "organization_created", `Se registró ${kind === "union" ? "el sindicato" : "el grupo"} ${name}.`, organization.id);
    return { id: organization.id };
  }

  if (action === "toggleOrganization") {
    requireAdmin(currentAccount);
    const id = value(payload.id, 64);
    const organization = database.unions.find((item) => item.id === id) || database.groups.find((item) => item.id === id);
    if (!organization) throw new AppError("No encontramos esa organización.", 404);
    if (organization.kind === "group" && !organization.active) {
      const parent = database.unions.find((item) => item.id === organization.parent_id);
      if (!parent?.active) throw new AppError("Primero debes reactivar el sindicato al que pertenece este grupo.");
    }
    organization.active = !organization.active;
    if (!organization.active) {
      for (const driver of database.drivers) {
        const belongs = organization.kind === "union" ? driver.union_id === id : driver.group_id === id;
        if (belongs && driver.status === "available") driver.status = "offline";
      }
    }
    record(database, currentAccount.email, "organization_updated", `${organization.active ? "Se activó" : "Se suspendió"} ${organization.name}.`, id);
    return;
  }

  if (action === "createDriver") {
    requireAdmin(currentAccount);
    const name = value(payload.name, 90);
    const accountEmail = email(payload.email);
    const phone = value(payload.phone, 20);
    const unionId = value(payload.unionId, 64);
    const groupId = value(payload.groupId, 64);
    const unitNumber = value(payload.unitNumber, 20).toUpperCase();
    const plate = value(payload.plate, 18).toUpperCase();
    const vehicle = value(payload.vehicle, 90);
    const password = String(payload.password || "");

    if (name.length < 3 || !validEmail(accountEmail) || phone.replace(/\D/g, "").length < 8 || !unionId || !unitNumber || !plate || !vehicle || password.length < 8) {
      throw new AppError("Completa nombre, correo, teléfono, sindicato, unidad, placas, vehículo y una contraseña de al menos 8 caracteres.");
    }
    if (database.users.some((item) => item.email === accountEmail)) throw new AppError("Ese correo ya tiene una cuenta registrada.", 409);
    if (database.drivers.some((item) => item.unit_number === unitNumber)) throw new AppError("Ya existe una unidad con ese número.", 409);
    if (!database.unions.some((item) => item.id === unionId && item.active)) throw new AppError("Selecciona un sindicato activo.");
    if (groupId && !database.groups.some((item) => item.id === groupId && item.parent_id === unionId && item.active)) {
      throw new AppError("El grupo seleccionado no pertenece a ese sindicato.");
    }

    const driver = {
      id: randomUUID(), name, email: accountEmail, phone, union_id: unionId, group_id: groupId || null,
      unit_number: unitNumber, plate, vehicle, vehicle_color: value(payload.vehicleColor, 40) || "Blanco",
      license_number: value(payload.licenseNumber, 40), permit_number: value(payload.permitNumber, 40),
      zone: value(payload.zone, 80) || "Turicato centro", status: "offline", verified: true, active: true,
      rating: 5, completed_trips: 0, created_at: date(),
    };
    database.drivers.push(driver);
    database.users.push({
      id: randomUUID(), name, email: accountEmail, phone, role: "driver", password_hash: hashPassword(password),
      active: true, created_at: date(),
    });
    record(database, currentAccount.email, "driver_created", `Se dio de alta a ${name}, unidad ${unitNumber}.`, driver.id);
    return { id: driver.id };
  }

  if (action === "toggleDriver") {
    requireAdmin(currentAccount);
    const driver = database.drivers.find((item) => item.id === value(payload.id, 64));
    if (!driver) throw new AppError("No encontramos a ese taxista.", 404);
    if (driver.active && database.rides.some((ride) => ride.driver_id === driver.id && ["accepted", "arrived", "in_progress"].includes(ride.status))) {
      throw new AppError("La unidad tiene un viaje activo; termínalo antes de suspenderla.", 409);
    }
    driver.active = !driver.active;
    driver.status = driver.active ? "offline" : "suspended";
    const user = database.users.find((item) => item.email === driver.email);
    if (user) user.active = driver.active;
    record(database, currentAccount.email, "driver_updated", `${driver.active ? "Se reactivó" : "Se suspendió"} la unidad ${driver.unit_number}.`, driver.id);
    return;
  }

  if (action === "resetDriverPassword") {
    requireAdmin(currentAccount);
    const driver = database.drivers.find((item) => item.id === value(payload.id, 64));
    const password = String(payload.password || "");
    if (!driver) throw new AppError("No encontramos a ese taxista.", 404);
    if (password.length < 8) throw new AppError("La contraseña debe tener al menos 8 caracteres.");
    const user = database.users.find((item) => item.email === driver.email);
    if (!user) throw new AppError("La cuenta del taxista ya no existe.", 404);
    user.password_hash = hashPassword(password);
    record(database, currentAccount.email, "driver_password_reset", `Se actualizó la contraseña de la unidad ${driver.unit_number}.`, driver.id);
    return;
  }

  if (action === "setDriverStatus") {
    if (!["admin", "driver"].includes(currentAccount.role)) throw new AppError("Acceso exclusivo de taxistas.", 403);
    const driver = database.drivers.find((item) => item.id === value(payload.driverId, 64));
    if (!driver?.active || !driver.verified || (currentAccount.role === "driver" && driver.email !== currentAccount.email)) {
      throw new AppError("No puedes modificar esta unidad.", 403);
    }
    const next = payload.status === "available" ? "available" : "offline";
    if (next === "available" && !driverOrganization(database, driver).operational) throw new AppError("El sindicato o grupo de esta unidad está suspendido.");
    if (next === "offline" && database.rides.some((ride) => ride.driver_id === driver.id && ["accepted", "arrived", "in_progress"].includes(ride.status))) {
      throw new AppError("Primero termina el viaje que tienes en curso.", 409);
    }
    driver.status = next;
    return;
  }

  if (action === "createRide") {
    if (currentAccount.role === "driver") throw new AppError("Los taxistas no pueden solicitar viajes desde su propia cuenta.", 403);
    if (!database.settings.service_enabled) throw new AppError("El servicio está temporalmente en pausa.", 409);
    if (database.rides.some((ride) => ride.passenger_email === currentAccount.email && ACTIVE_RIDES.has(ride.status))) {
      throw new AppError("Ya tienes un viaje en curso.", 409);
    }
    const pickupLabel = value(payload.pickupLabel, 120);
    const destinationLabel = value(payload.destinationLabel, 120);
    const pickupLat = number(payload.pickupLat, NaN);
    const pickupLng = number(payload.pickupLng, NaN);
    const destinationLat = number(payload.destinationLat, NaN);
    const destinationLng = number(payload.destinationLng, NaN);
    if (pickupLabel.length < 3 || destinationLabel.length < 3 || ![pickupLat, pickupLng, destinationLat, destinationLng].every(Number.isFinite) ||
      Math.abs(pickupLat) > 90 || Math.abs(destinationLat) > 90 || Math.abs(pickupLng) > 180 || Math.abs(destinationLng) > 180) {
      throw new AppError("Marca correctamente la partida y el destino.");
    }
    const distance = Math.max(.3, Math.round(coordinatesDistance(pickupLat, pickupLng, destinationLat, destinationLng) * 1.32 * 10) / 10);
    if (distance > 120) throw new AppError("El destino está fuera del área disponible.");
    const fare = Math.max(number(database.settings.minimum_fare, 45), Math.round(number(database.settings.base_fare, 35) + distance * number(database.settings.fare_per_km, 11)));
    const ride = {
      id: randomUUID(), folio: `TUR-${Date.now().toString().slice(-6)}${randomInt(10)}`,
      passenger_email: currentAccount.email, passenger_name: currentAccount.name, passenger_phone: currentAccount.phone,
      driver_id: null, pickup_label: pickupLabel, pickup_lat: pickupLat, pickup_lng: pickupLng,
      destination_label: destinationLabel, destination_lat: destinationLat, destination_lng: destinationLng,
      distance_km: distance, estimated_fare: fare, final_fare: null, status: "requested",
      payment_method: payload.paymentMethod === "transfer" ? "transfer" : "cash",
      passengers: Math.max(1, Math.min(4, Math.round(number(payload.passengers, 1)))),
      notes: value(payload.notes, 240), security_code: String(randomInt(1000, 10000)), rating: null,
      created_at: date(), updated_at: date(), accepted_at: null, completed_at: null,
    };
    database.rides.unshift(ride);
    record(database, currentAccount.email, "ride_requested", `Se solicitó el viaje ${ride.folio}: ${pickupLabel} → ${destinationLabel}.`, ride.id);
    return { id: ride.id, folio: ride.folio };
  }

  if (action === "acceptRide") {
    if (!["admin", "driver"].includes(currentAccount.role)) throw new AppError("Acceso exclusivo de taxistas.", 403);
    const ride = database.rides.find((item) => item.id === value(payload.rideId, 64));
    const driver = database.drivers.find((item) => item.id === value(payload.driverId, 64));
    if (!ride || ride.status !== "requested") throw new AppError("Otro taxista ya aceptó este servicio.", 409);
    if (!driver?.active || !driver.verified || driver.status !== "available" || !driverOrganization(database, driver).operational ||
      (currentAccount.role === "driver" && driver.email !== currentAccount.email)) {
      throw new AppError("La unidad debe estar disponible y autorizada.", 409);
    }
    ride.driver_id = driver.id;
    ride.status = "accepted";
    ride.accepted_at = date();
    ride.updated_at = ride.accepted_at;
    driver.status = "busy";
    record(database, currentAccount.email, "ride_accepted", `La unidad ${driver.unit_number} aceptó el viaje ${ride.folio}.`, ride.id);
    return;
  }

  if (action === "advanceRide") {
    if (!["admin", "driver"].includes(currentAccount.role)) throw new AppError("Acceso exclusivo de taxistas.", 403);
    const ride = database.rides.find((item) => item.id === value(payload.rideId, 64));
    const driver = ride?.driver_id ? database.drivers.find((item) => item.id === ride.driver_id) : null;
    if (!ride || !driver || (currentAccount.role === "driver" && driver.email !== currentAccount.email)) throw new AppError("Este viaje corresponde a otra unidad.", 403);
    const next = { accepted: "arrived", arrived: "in_progress", in_progress: "completed" }[ride.status];
    if (!next) throw new AppError("El viaje ya no puede avanzar.", 409);
    if (next === "in_progress" && value(payload.securityCode, 8) !== ride.security_code) throw new AppError("El código de seguridad no coincide.");
    ride.status = next;
    ride.updated_at = date();
    if (next === "completed") {
      ride.completed_at = ride.updated_at;
      ride.final_fare = ride.estimated_fare;
      driver.completed_trips += 1;
      driver.status = "available";
    }
    const messages = { arrived: "La unidad llegó al punto de partida.", in_progress: "Se verificó el código y comenzó el viaje.", completed: "El viaje se completó correctamente." };
    record(database, currentAccount.email, "ride_updated", messages[next], ride.id);
    return;
  }

  if (action === "cancelRide") {
    const ride = database.rides.find((item) => item.id === value(payload.rideId, 64));
    if (!ride) throw new AppError("No encontramos ese viaje.", 404);
    const driver = ride.driver_id ? database.drivers.find((item) => item.id === ride.driver_id) : null;
    if (currentAccount.role !== "admin" && ride.passenger_email !== currentAccount.email && driver?.email !== currentAccount.email) {
      throw new AppError("No puedes cancelar este viaje.", 403);
    }
    if (!["requested", "accepted", "arrived"].includes(ride.status)) throw new AppError("Este viaje ya no puede cancelarse.", 409);
    ride.status = "cancelled";
    ride.updated_at = date();
    if (driver?.active) driver.status = "available";
    record(database, currentAccount.email, "ride_cancelled", `Se canceló el viaje ${ride.folio}.`, ride.id);
    return;
  }

  if (action === "rateRide") {
    const ride = database.rides.find((item) => item.id === value(payload.rideId, 64));
    if (!ride || ride.passenger_email !== currentAccount.email || ride.status !== "completed" || !ride.driver_id) {
      throw new AppError("Solo puedes calificar tus viajes terminados.", 403);
    }
    ride.rating = Math.max(1, Math.min(5, Math.round(number(payload.rating, 5))));
    const driver = database.drivers.find((item) => item.id === ride.driver_id);
    const ratings = database.rides.filter((item) => item.driver_id === ride.driver_id && item.rating).map((item) => item.rating);
    if (driver && ratings.length) driver.rating = Math.round(ratings.reduce((sum, item) => sum + item, 0) / ratings.length * 10) / 10;
    return;
  }

  if (action === "saveSettings") {
    requireAdmin(currentAccount);
    database.settings = {
      base_fare: Math.max(0, Math.min(2000, number(payload.baseFare, 35))),
      fare_per_km: Math.max(0, Math.min(1000, number(payload.farePerKm, 11))),
      minimum_fare: Math.max(0, Math.min(2000, number(payload.minimumFare, 45))),
      service_enabled: payload.serviceEnabled !== false,
      support_phone: value(payload.supportPhone, 20),
      service_area: value(payload.serviceArea, 90) || "Turicato, Michoacán",
    };
    record(database, currentAccount.email, "settings_updated", "Se actualizó la configuración del servicio.");
    return;
  }

  throw new AppError("Acción no reconocida.", 400);
}

export default async function handler(request) {
  try {
    const configuration = requireConfiguration();
    const database = await ensureAdministrator(configuration);

    if (request.method === "GET") {
      const account = signedInAccount(request, database, configuration);
      return account ? response(visibleState(database, account)) : response({ authenticated: false });
    }

    if (request.method !== "POST") return response({ error: "Método no permitido." }, 405);
    const origin = request.headers.get("origin");
    if (origin && origin !== new URL(request.url).origin) throw new AppError("Solicitud de origen no autorizado.", 403);
    if (!request.headers.get("content-type")?.toLowerCase().includes("application/json")) throw new AppError("El contenido debe enviarse como JSON.", 415);
    const contentLength = Number(request.headers.get("content-length") || 0);
    if (contentLength > 256_000) throw new AppError("La solicitud es demasiado grande.", 413);

    const payload = await request.json();
    const action = value(payload.action, 40);

    if (action === "login") return await login(request, payload, configuration, database);
    if (action === "registerPassenger") return await registerPassenger(request, payload, configuration);
    if (action === "logout") return response({ ok: true }, 200, { "Set-Cookie": cookie(request, "", 0) });

    const account = signedInAccount(request, database, configuration);
    if (!account) throw new AppError("Tu sesión venció. Inicia sesión nuevamente.", 401);

    const saved = await transaction((current) => performAction(current, account, action, payload));
    return response({ ok: true, ...(saved.result || {}) });
  } catch (error) {
    if (error instanceof AppError) return response({ error: error.message }, error.status);
    console.error("Taxi Turicato server error:", error);
    return response({ error: "No fue posible completar la operación. Inténtalo nuevamente." }, 500);
  }
}

export const config = { path: "/api/taxi" };

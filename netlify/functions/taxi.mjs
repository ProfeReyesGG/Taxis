import { getStore } from "@netlify/blobs";
import { createHash, createHmac, randomBytes, randomInt, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";

const STORE_NAME = "taxi-turicato";
const MEDIA_STORE_NAME = "taxi-turicato-fotografias";
const DATABASE_KEY = "central-operativa-v1";
const COOKIE_NAME = "taxi_turicato";
const SESSION_SECONDS = 60 * 60 * 24 * 7;
const LEGAL_VERSION = "2026-08-24";
const MAX_IMAGE_BYTES = 650_000;
const ACTIVE_RIDES = new Set(["requested", "accepted", "arrived", "in_progress"]);
const COLORS = new Set(["#134738", "#537dd5", "#d58237", "#9556a1", "#bd4f5a", "#438e80"]);

const DEFAULT_SETTINGS = {
  base_fare: 35,
  fare_per_km: 11,
  minimum_fare: 45,
  service_enabled: true,
  support_phone: "",
  service_area: "Turicato, Michoacán",
  pickup_fee: 15,
  default_eta_minutes: 12,
  responsible_name: "",
  responsible_address: "",
  privacy_email: "",
  incident_phone: "",
  data_retention_days: 365,
  pilot_mode: true,
  legal_review_confirmed: false,
  transport_authorization_confirmed: false,
  insurance_required: true,
  senior_discount: 10,
  student_discount: 10,
  discounts_authorized: false,
  child_free_max_age: 2,
  child_fare_authorized: false,
  special_max_per_person: 120,
  site_dispatch_start: "07:00",
  site_dispatch_end: "20:00",
  site_exclusion_meters: 80,
  allow_driver_claim: true,
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

  const issues = [];
  if (!administrator) issues.push("TAXI_ADMIN_EMAIL no está llegando a Functions");
  else if (!validEmail(administrator)) issues.push("TAXI_ADMIN_EMAIL no contiene un correo válido");
  if (!password) issues.push("TAXI_ADMIN_PASSWORD no está llegando a Functions");
  else if (password.length < 12) issues.push("TAXI_ADMIN_PASSWORD debe tener al menos 12 caracteres");
  if (!secret) issues.push("TAXI_SESSION_SECRET no está llegando a Functions; revisa que empiece con TAXI_");
  else if (secret.length < 32) issues.push("TAXI_SESSION_SECRET debe tener al menos 32 caracteres");
  if (issues.length) throw new AppError(`Configuración de Netlify incompleta: ${issues.join("; ")}.`, 503);

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
    version: 2,
    users: [],
    unions: [],
    groups: [],
    sites: [],
    drivers: [],
    tariffs: [],
    reports: [],
    rides: [],
    activity: [],
    login_attempts: {},
    settings: { ...DEFAULT_SETTINGS },
  };
}

function normalizeDatabase(database) {
  const safe = database && typeof database === "object" ? database : emptyDatabase();
  for (const key of ["users", "unions", "groups", "sites", "drivers", "tariffs", "rides", "reports", "activity"]) {
    if (!Array.isArray(safe[key])) safe[key] = [];
  }
  if (!safe.login_attempts || typeof safe.login_attempts !== "object") safe.login_attempts = {};
  safe.settings = { ...DEFAULT_SETTINGS, ...(safe.settings || {}) };
  safe.version = 2;
  return safe;
}

function blobStore() {
  return getStore({ name: STORE_NAME, consistency: "strong" });
}

function mediaStore() {
  return getStore({ name: MEDIA_STORE_NAME, consistency: "strong" });
}

async function snapshot() {
  const entry = await blobStore().getWithMetadata(DATABASE_KEY, { type: "json", consistency: "strong" });
  if (!entry) return { data: emptyDatabase(), etag: null };
  return { data: normalizeDatabase(entry.data), etag: entry.etag };
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
  const { password_hash: _passwordHash, profile_photo_key: profilePhotoKey, ...safe } = account;
  safe.profile_photo_url = profilePhotoKey ? `/api/taxi?photo=${encodeURIComponent(profilePhotoKey)}` : "";
  return safe;
}

function driverOrganization(database, driver) {
  const union = database.unions.find((item) => item.id === driver.union_id);
  const group = driver.group_id ? database.groups.find((item) => item.id === driver.group_id) : null;
  const site = driver.site_id ? database.sites.find((item) => item.id === driver.site_id) : null;
  const insuranceValid = !database.settings.insurance_required || Boolean(
    driver.insurance_policy && driver.insurance_expiration && driver.insurance_expiration >= date().slice(0, 10),
  );
  const documentsValid = Boolean(driver.license_number && driver.permit_number && insuranceValid);
  return {
    union,
    group,
    site,
    insuranceValid,
    documentsValid,
    operational: Boolean(union?.active && (!driver.group_id || group?.active) && (!driver.site_id || site?.active) && documentsValid),
  };
}

function enrichedDriver(database, driver, privateFields = false) {
  const { union, group, site, insuranceValid, documentsValid } = driverOrganization(database, driver);
  const enriched = {
    ...driver,
    union_name: union?.name || "",
    group_name: group?.name || "",
    site_name: site?.name || "",
    insurance_valid: insuranceValid,
    documents_valid: documentsValid,
    driver_photo_url: driver.driver_photo_key ? `/api/taxi?photo=${encodeURIComponent(driver.driver_photo_key)}` : "",
    vehicle_photo_url: driver.vehicle_photo_key ? `/api/taxi?photo=${encodeURIComponent(driver.vehicle_photo_key)}` : "",
  };
  if (!privateFields) {
    delete enriched.email;
    delete enriched.phone;
    delete enriched.license_number;
    delete enriched.permit_number;
    delete enriched.insurance_policy;
    delete enriched.insurance_expiration;
    delete enriched.driver_photo_key;
    delete enriched.vehicle_photo_key;
    delete enriched.consent_recorded_by;
    delete enriched.consent_recorded_at;
  }
  return enriched;
}

function enrichedRide(database, ride) {
  const driver = ride.driver_id ? database.drivers.find((item) => item.id === ride.driver_id) : null;
  const site = ride.site_id ? database.sites.find((item) => item.id === ride.site_id) : null;
  const passenger = database.users.find((item) => item.email === ride.passenger_email && item.role === "passenger");
  const base = {
    ...ride,
    site_name: site?.name || ride.site_name || "",
    site_phone: site?.phone || "",
    site_town: site?.town || "",
    site_photo_url: site?.photo_key ? `/api/taxi?photo=${encodeURIComponent(site.photo_key)}` : "",
    passenger_photo_url: passenger?.profile_photo_key ? `/api/taxi?photo=${encodeURIComponent(passenger.profile_photo_key)}` : "",
    pickup_photo_url: ride.pickup_photo_key ? `/api/taxi?photo=${encodeURIComponent(ride.pickup_photo_key)}` : "",
  };
  if (!driver) return base;
  const { union, group } = driverOrganization(database, driver);
  return {
    ...base,
    driver_name: driver.name,
    driver_phone: driver.phone,
    driver_unit: driver.unit_number,
    driver_plate: driver.plate,
    driver_vehicle: driver.vehicle,
    driver_vehicle_color: driver.vehicle_color,
    driver_rating: driver.rating,
    driver_photo_url: driver.driver_photo_key ? `/api/taxi?photo=${encodeURIComponent(driver.driver_photo_key)}` : "",
    vehicle_photo_url: driver.vehicle_photo_key ? `/api/taxi?photo=${encodeURIComponent(driver.vehicle_photo_key)}` : "",
    union_name: union?.name || "",
    group_name: group?.name || "",
  };
}

function publicOrganization(item) {
  return { id: item.id, name: item.name, color: item.color, active: item.active, parent_id: item.parent_id || null };
}

function publicSite(item) {
  return {
    id: item.id,
    name: item.name,
    town: item.town,
    address: item.address,
    phone: item.phone,
    union_id: item.union_id || null,
    active: item.active,
    eta_default_minutes: item.eta_default_minutes,
    photo_url: item.photo_key ? `/api/taxi?photo=${encodeURIComponent(item.photo_key)}` : "",
    dispatch_start: item.dispatch_start,
    dispatch_end: item.dispatch_end,
    base_lat: item.base_lat ?? null,
    base_lng: item.base_lng ?? null,
  };
}

function legalReady(settings) {
  return Boolean(
    value(settings.responsible_name, 120).length >= 3 &&
    value(settings.responsible_address, 180).length >= 8 &&
    validEmail(email(settings.privacy_email)) &&
    settings.legal_review_confirmed &&
    settings.transport_authorization_confirmed,
  );
}

function publicLegalSettings(settings) {
  return {
    responsible_name: settings.responsible_name,
    responsible_address: settings.responsible_address,
    privacy_email: settings.privacy_email,
    incident_phone: settings.incident_phone || settings.support_phone,
    support_phone: settings.support_phone,
    service_area: settings.service_area,
    data_retention_days: settings.data_retention_days,
    pilot_mode: settings.pilot_mode,
    legal_version: LEGAL_VERSION,
    legal_ready: legalReady(settings),
  };
}

function visibleState(database, account) {
  const ownDriver = account.role === "driver" ? database.drivers.find((driver) => driver.email === account.email) : null;
  const ownSite = account.role === "site" ? database.sites.find((site) => site.id === account.site_id) : null;
  if (account.role === "driver" && (!ownDriver || !ownDriver.active || !ownDriver.verified)) {
    throw new AppError("Tu unidad no está autorizada. Comunícate con administración.", 403);
  }
  if (account.role === "site" && (!ownSite || !ownSite.active)) {
    throw new AppError("Este sitio está suspendido o no tiene autorización vigente.", 403);
  }

  let drivers = [];
  let rides = [];
  let sites = [];
  let tariffs = [];
  let activity = [];
  let reports = [];
  let passengers = [];

  if (account.role === "admin") {
    drivers = database.drivers.map((driver) => enrichedDriver(database, driver, true));
    rides = database.rides.map((ride) => enrichedRide(database, ride));
    sites = database.sites.map((site) => ({ ...site, photo_url: publicSite(site).photo_url }));
    tariffs = database.tariffs;
    activity = database.activity.slice(0, 60);
    reports = database.reports;
    passengers = database.users.filter((item) => item.role === "passenger").map(accountWithoutSecrets);
  } else if (account.role === "site") {
    drivers = database.drivers.filter((driver) => driver.site_id === ownSite.id).map((driver) => enrichedDriver(database, driver, true));
    rides = database.rides.filter((ride) => ride.site_id === ownSite.id).map((ride) => {
      const safe = enrichedRide(database, ride);
      delete safe.security_code;
      delete safe.route_events;
      if (!["requested", "accepted", "arrived", "in_progress"].includes(ride.status)) {
        delete safe.pickup_lat;
        delete safe.pickup_lng;
        delete safe.pickup_photo_url;
        delete safe.pickup_photo_key;
      }
      return safe;
    });
    sites = [{ ...ownSite, photo_url: publicSite(ownSite).photo_url }];
    tariffs = database.tariffs.filter((tariff) => tariff.active && samePlace(tariff.town, ownSite.town));
    const related = new Set([ownSite.id, ...drivers.map((driver) => driver.id), ...rides.map((ride) => ride.id)]);
    activity = database.activity.filter((item) => item.actor_email === account.email || related.has(item.related_id)).slice(0, 30);
    reports = database.reports.filter((report) => report.site_id === ownSite.id);
    const ownPassengerEmails = new Set(rides.map((ride) => ride.passenger_email));
    passengers = database.users.filter((item) => item.role === "passenger" && ownPassengerEmails.has(item.email)).map(accountWithoutSecrets);
  } else if (account.role === "driver") {
    drivers = [enrichedDriver(database, ownDriver, true)];
    rides = database.rides
      .filter((ride) => ride.driver_id === ownDriver.id ||
        (database.settings.allow_driver_claim && ownDriver.status === "available" && ride.status === "requested" && ride.site_id === ownDriver.site_id))
      .map((ride) => {
        const safe = enrichedRide(database, ride);
        delete safe.security_code;
        delete safe.route_events;
        if (ride.driver_id !== ownDriver.id) {
          delete safe.passenger_email;
          delete safe.passenger_phone;
          delete safe.passenger_photo_url;
          delete safe.pickup_photo_url;
          delete safe.pickup_lat;
          delete safe.pickup_lng;
          delete safe.pickup_photo_key;
        } else if (!ACTIVE_RIDES.has(ride.status)) {
          delete safe.pickup_lat;
          delete safe.pickup_lng;
          delete safe.pickup_photo_url;
          delete safe.pickup_photo_key;
          delete safe.passenger_photo_url;
          delete safe.passenger_phone;
        }
        return safe;
      });
    sites = database.sites.filter((site) => site.id === ownDriver.site_id).map(publicSite);
    tariffs = database.tariffs.filter((tariff) => tariff.active && sites.some((site) => samePlace(site.town, tariff.town)));
    reports = database.reports.filter((report) => report.driver_id === ownDriver.id).map(({ passenger_name: _name, passenger_email: _email, details: _details, ...safe }) => safe);
  } else {
    drivers = database.drivers
      .filter((driver) => driver.active && driver.verified && driver.status === "available" && driverOrganization(database, driver).operational)
      .map((driver) => enrichedDriver(database, driver));
    rides = database.rides.filter((ride) => ride.passenger_email === account.email).map((ride) => {
      const safe = enrichedRide(database, ride);
      delete safe.route_events;
      if (!ACTIVE_RIDES.has(ride.status)) {
        delete safe.pickup_lat;
        delete safe.pickup_lng;
      }
      return safe;
    });
    sites = database.sites.filter((site) => site.active).map(publicSite);
    tariffs = database.tariffs.filter((tariff) => tariff.active && sites.some((site) => samePlace(site.town, tariff.town)));
    reports = database.reports.filter((report) => report.passenger_email === account.email);
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
    ownSite: ownSite ? { ...ownSite, photo_url: publicSite(ownSite).photo_url } : null,
    unions: account.role === "admin" ? database.unions : database.unions.filter((item) => item.active).map(publicOrganization),
    groups: account.role === "admin" ? database.groups : database.groups.filter((item) => item.active).map(publicOrganization),
    sites,
    tariffs,
    drivers,
    rides,
    passengers,
    reports,
    activity,
    audit_log: account.role === "admin" ? database.activity : [],
    settings: database.settings,
    legal: publicLegalSettings(database.settings),
    route_history: account.role === "admin" ? database.rides.map((ride) => ({
      id: ride.id,
      folio: ride.folio,
      site_id: ride.site_id || null,
      site_name: database.sites.find((site) => site.id === ride.site_id)?.name || "Sin sitio asignado",
      driver_name: database.drivers.find((driver) => driver.id === ride.driver_id)?.name || "",
      pickup_label: ride.pickup_label,
      pickup_lat: ride.pickup_lat,
      pickup_lng: ride.pickup_lng,
      destination_label: ride.destination_label,
      destination_lat: ride.destination_lat ?? null,
      destination_lng: ride.destination_lng ?? null,
      events: ride.route_events || [],
      created_at: ride.created_at,
      status: ride.status,
    })) : [],
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

function samePlace(first, second) {
  const normalize = (item) => value(item, 120).normalize("NFD").replace(/\p{Diacritic}/gu, "").toLowerCase().replace(/\s+/g, " ");
  return normalize(first) === normalize(second);
}

function routeEvent(ride, actor, action, details = "") {
  if (!Array.isArray(ride.route_events)) ride.route_events = [];
  ride.route_events.push({ at: date(), actor, action, details: value(details, 180) });
  ride.route_events = ride.route_events.slice(-40);
}

function accountSite(database, account) {
  if (account.role !== "site") return null;
  return database.sites.find((site) => site.id === account.site_id && site.active) || null;
}

function requireSiteOrAdmin(database, account, siteId) {
  if (account.role === "admin") return null;
  const site = accountSite(database, account);
  if (!site || site.id !== siteId) throw new AppError("Solo el sitio responsable o la administración pueden realizar esta acción.", 403);
  return site;
}

function optionalCoordinate(input, max) {
  if (input === null || input === undefined || input === "") return null;
  const parsed = number(input, NaN);
  if (!Number.isFinite(parsed) || Math.abs(parsed) > max) throw new AppError("La coordenada del destino no es válida.");
  return Math.round(parsed * 1_000_000) / 1_000_000;
}

function validTime(input, fallback) {
  const candidate = value(input, 5);
  return /^([01]\d|2[0-3]):[0-5]\d$/.test(candidate) ? candidate : fallback;
}

function withinSchedule(start, end) {
  const parts = new Intl.DateTimeFormat("en-GB", { timeZone: "America/Mexico_City", hour: "2-digit", minute: "2-digit", hour12: false }).formatToParts(new Date());
  const now = `${parts.find((part) => part.type === "hour")?.value}:${parts.find((part) => part.type === "minute")?.value}`;
  return start === end || (start < end ? now >= start && now <= end : now >= start || now <= end);
}

function metersBetween(firstLat, firstLng, secondLat, secondLng) {
  const radians = Math.PI / 180;
  const latitude = (secondLat - firstLat) * radians;
  const longitude = (secondLng - firstLng) * radians;
  const root = Math.sin(latitude / 2) ** 2 + Math.cos(firstLat * radians) * Math.cos(secondLat * radians) * Math.sin(longitude / 2) ** 2;
  return 12_742_000 * Math.atan2(Math.sqrt(root), Math.sqrt(1 - root));
}

function normalizedTariff(payload, settings) {
  const town = value(payload.town || payload.municipio || payload.localidad, 90);
  const origin = value(payload.origin || payload.origen || "Centro", 100);
  const destination = value(payload.destination || payload.destino, 110);
  const serviceFare = number(payload.serviceFare ?? payload.fare ?? payload.tarifa, NaN);
  const pickupInput = payload.pickupFee ?? payload.recogida;
  const pickupFee = pickupInput === "" || pickupInput === null || pickupInput === undefined
    ? number(settings.pickup_fee, 15)
    : number(pickupInput, NaN);
  const etaInput = payload.etaMinutes ?? payload.eta_min;
  const etaMinutes = etaInput === "" || etaInput === null || etaInput === undefined
    ? number(settings.default_eta_minutes, 12)
    : number(etaInput, NaN);
  if (town.length < 3 || origin.length < 2 || destination.length < 3 ||
    !Number.isFinite(serviceFare) || serviceFare < 0 || serviceFare > 20_000 ||
    !Number.isFinite(pickupFee) || pickupFee < 0 || pickupFee > 5_000 ||
    !Number.isFinite(etaMinutes) || etaMinutes < 1 || etaMinutes > 240) {
    throw new AppError("Cada tarifa debe indicar localidad, origen, destino, importe válido, recogida y tiempo estimado.");
  }
  return {
    town,
    origin,
    destination,
    service_fare: Math.round(serviceFare * 100) / 100,
    pickup_fee: Math.round(pickupFee * 100) / 100,
    eta_minutes: Math.round(etaMinutes),
    destination_lat: optionalCoordinate(payload.destinationLat ?? payload.latitud, 90),
    destination_lng: optionalCoordinate(payload.destinationLng ?? payload.longitud, 180),
    arrival_point: value(payload.arrivalPoint ?? payload.llegada, 120) || `Plaza principal de ${destination}`,
    price_mode: payload.priceMode === "trip" || payload.modo === "viaje" ? "trip" : "person",
    recommended: payload.recommended === false || String(payload.recommended).toLowerCase() === "false" ||
      ["no", "false", "0"].includes(String(payload.recomendado).toLowerCase()) ? false : true,
    student_discount: Math.max(0, Math.min(500, number(payload.studentDiscount ?? payload.descuento_estudiante, settings.student_discount))),
  };
}

function imageKind(buffer, claimed) {
  if (buffer.length < 12) return "";
  const jpeg = buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  const png = buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  const webp = buffer.subarray(0, 4).toString() === "RIFF" && buffer.subarray(8, 12).toString() === "WEBP";
  if (jpeg && claimed === "image/jpeg") return "jpg";
  if (png && claimed === "image/png") return "png";
  if (webp && claimed === "image/webp") return "webp";
  return "";
}

async function persistPhoto(account, payload, allowedKinds) {
  const role = allowedKinds.includes(payload.kind) ? payload.kind : "";
  const encoded = value(payload.data, MAX_IMAGE_BYTES * 2);
  const mime = value(payload.mime, 30);
  if (!role || !encoded || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    throw new AppError("Selecciona una fotografía válida en formato JPG, PNG o WebP.");
  }
  const bytes = Buffer.from(encoded, "base64");
  if (!bytes.length || bytes.length > MAX_IMAGE_BYTES) throw new AppError("La fotografía debe pesar menos de 650 KB después de optimizarse.", 413);
  const extension = imageKind(bytes, mime);
  if (!extension) throw new AppError("La fotografía debe estar en formato JPG, PNG o WebP.");
  const key = `${role}/${randomUUID()}.${extension}`;
  await mediaStore().set(key, bytes, { metadata: { contentType: mime, uploadedBy: account.email, createdAt: date() } });
  return { key, url: `/api/taxi?photo=${encodeURIComponent(key)}` };
}

async function uploadPhoto(database, account, payload) {
  const allowed = account.role === "admin" ? ["driver", "vehicle", "site"] :
    account.role === "passenger" ? ["passenger", "pickup"] : [];
  if (!allowed.length) throw new AppError("Tu cuenta no puede subir este tipo de fotografía.", 403);
  return response({ ok: true, ...(await persistPhoto(account, payload, allowed)) }, 201);
}

async function servePhoto(database, account, key) {
  if (!/^(driver|vehicle|site|passenger|pickup)\/[a-f0-9-]{36}\.(jpg|png|webp)$/.test(key)) throw new AppError("Fotografía no encontrada.", 404);
  const driver = database.drivers.find((item) => item.driver_photo_key === key || item.vehicle_photo_key === key);
  const site = database.sites.find((item) => item.photo_key === key);
  const passenger = database.users.find((item) => item.profile_photo_key === key);
  const ride = database.rides.find((item) => item.pickup_photo_key === key);
  if (!driver && !site && !passenger && !ride) throw new AppError("Fotografía no encontrada.", 404);

  const relatedRide = passenger ? database.rides.find((item) => item.passenger_email === passenger.email &&
    ((account.role === "site" && item.site_id === account.site_id) ||
     (account.role === "driver" && ACTIVE_RIDES.has(item.status) && database.drivers.find((candidate) => candidate.email === account.email)?.id === item.driver_id))) : null;
  const allowed = account.role === "admin" || Boolean(site) ||
    (driver && ((account.role === "site" && account.site_id === driver.site_id) ||
      (account.role === "driver" && account.email === driver.email) ||
      (account.role === "passenger" && database.rides.some((item) => item.passenger_email === account.email && item.driver_id === driver.id)))) ||
    (passenger && (account.email === passenger.email || relatedRide)) ||
    (ride && (ride.passenger_email === account.email || (account.role === "site" && ride.site_id === account.site_id) ||
      (account.role === "driver" && ACTIVE_RIDES.has(ride.status) && ride.driver_id === database.drivers.find((item) => item.email === account.email)?.id)));
  if (!allowed) throw new AppError("No tienes permiso para consultar esta fotografía.", 403);

  const entry = await mediaStore().getWithMetadata(key, { type: "arrayBuffer", consistency: "strong" });
  if (!entry) throw new AppError("Fotografía no encontrada.", 404);
  return new Response(entry.data, {
    status: 200,
    headers: {
      "Content-Type": entry.metadata?.contentType || "image/jpeg",
      "Cache-Control": "private, max-age=300",
      "X-Content-Type-Options": "nosniff",
    },
  });
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
  if (payload.privacyAccepted !== true || payload.termsAccepted !== true) {
    throw new AppError("Debes leer y aceptar el aviso de privacidad y los términos del servicio.", 400);
  }
  if (accountEmail === configuration.administrator) throw new AppError("Ese correo está reservado para administración.", 409);

  const prospective = { email: accountEmail };
  const photo = await persistPhoto(prospective, { ...payload.profilePhoto, kind: "passenger" }, ["passenger"]);

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
      profile_photo_key: photo.key,
      senior_discount_eligible: payload.seniorEligible === true,
      active: true,
      privacy_accepted_at: date(),
      terms_accepted_at: date(),
      legal_version: LEGAL_VERSION,
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
    if (currentAccount.role === "passenger") {
      currentAccount.senior_discount_eligible = payload.seniorEligible === true;
      if (payload.profilePhotoKey) {
        const key = value(payload.profilePhotoKey, 80);
        if (!/^passenger\/[a-f0-9-]{36}\.(jpg|png|webp)$/.test(key)) throw new AppError("La fotografía del pasajero no es válida.");
        currentAccount.profile_photo_key = key;
      }
    }
    if (currentAccount.role === "driver") {
      const driver = database.drivers.find((item) => item.email === currentAccount.email);
      if (driver) { driver.name = name; driver.phone = phone; }
    }
    if (currentAccount.role === "site") {
      const site = database.sites.find((item) => item.id === currentAccount.site_id);
      if (site) site.phone = phone;
    }
    record(database, currentAccount.email, "profile_updated", `Se actualizaron datos del perfil ${currentAccount.role}.`, currentAccount.id);
    return;
  }

  if (action === "acceptLegal") {
    if (payload.privacyAccepted !== true || payload.termsAccepted !== true) {
      throw new AppError("Debes aceptar expresamente el aviso de privacidad y los términos correspondientes.");
    }
    currentAccount.privacy_accepted_at = date();
    currentAccount.terms_accepted_at = currentAccount.privacy_accepted_at;
    currentAccount.legal_version = LEGAL_VERSION;
    record(database, currentAccount.email, "legal_accepted", "Se registró la aceptación de documentos de privacidad y condiciones de uso.", currentAccount.id);
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

  if (["site", "driver"].includes(currentAccount.role) &&
      (!currentAccount.privacy_accepted_at || !currentAccount.terms_accepted_at || currentAccount.legal_version !== LEGAL_VERSION)) {
    throw new AppError("Debes leer y aceptar primero el aviso de privacidad y las condiciones de operación.", 403);
  }

  if (currentAccount.role === "site") {
    const scheduledSite = accountSite(database, currentAccount);
    if (!scheduledSite || !withinSchedule(scheduledSite.dispatch_start || database.settings.site_dispatch_start,
      scheduledSite.dispatch_end || database.settings.site_dispatch_end)) {
      throw new AppError("El sitio solo puede administrar operaciones dentro del horario autorizado por la administración maestra.", 403);
    }
  }

  if (action === "createSite") {
    requireAdmin(currentAccount);
    const name = value(payload.name, 100);
    const town = value(payload.town, 90);
    const accountEmail = email(payload.email);
    const phone = value(payload.phone, 20).replace(/[^\d+\s()-]/g, "");
    const unionId = value(payload.unionId, 64);
    const password = String(payload.password || "");
    if (name.length < 3 || town.length < 3 || !validEmail(accountEmail) || phone.replace(/\D/g, "").length < 8 || password.length < 8) {
      throw new AppError("Completa nombre del sitio, localidad, correo, teléfono y una contraseña de al menos 8 caracteres.");
    }
    if (database.users.some((item) => item.email === accountEmail)) throw new AppError("Ese correo ya está registrado en otra cuenta.", 409);
    if (database.sites.some((site) => samePlace(site.name, name) && samePlace(site.town, town))) {
      throw new AppError("Ya existe un sitio con ese nombre en esta localidad.", 409);
    }
    if (unionId && !database.unions.some((union) => union.id === unionId && union.active)) {
      throw new AppError("El sindicato seleccionado debe estar activo.");
    }
    const photoKey = value(payload.sitePhotoKey, 80);
    if (!/^site\/[a-f0-9-]{36}\.(jpg|png|webp)$/.test(photoKey)) {
      throw new AppError("La fotografía del sitio es obligatoria para autorizar su perfil.");
    }
    const site = {
      id: randomUUID(),
      name,
      town,
      email: accountEmail,
      phone,
      address: value(payload.address, 160),
      union_id: unionId || null,
      manager_name: value(payload.managerName, 90) || name,
      eta_default_minutes: Math.max(1, Math.min(120, Math.round(number(payload.etaMinutes, database.settings.default_eta_minutes)))),
      photo_key: photoKey,
      dispatch_start: validTime(payload.dispatchStart, database.settings.site_dispatch_start),
      dispatch_end: validTime(payload.dispatchEnd, database.settings.site_dispatch_end),
      base_lat: optionalCoordinate(payload.baseLat, 90),
      base_lng: optionalCoordinate(payload.baseLng, 180),
      active: true,
      verified: true,
      created_at: date(),
    };
    database.sites.push(site);
    database.users.push({
      id: randomUUID(), name: site.manager_name, email: accountEmail, phone, role: "site", site_id: site.id,
      password_hash: hashPassword(password), active: true, created_at: date(),
    });
    record(database, currentAccount.email, "site_created", `Se autorizó ${name} en ${town}.`, site.id);
    return { id: site.id };
  }

  if (action === "toggleSite") {
    requireAdmin(currentAccount);
    const site = database.sites.find((item) => item.id === value(payload.id, 64));
    if (!site) throw new AppError("No encontramos ese sitio de taxis.", 404);
    if (site.active && database.rides.some((ride) => ride.site_id === site.id && ["accepted", "arrived", "in_progress"].includes(ride.status))) {
      throw new AppError("El sitio tiene viajes activos. Debe terminarlos antes de suspenderlo.", 409);
    }
    site.active = !site.active;
    const manager = database.users.find((user) => user.role === "site" && user.site_id === site.id);
    if (manager) manager.active = site.active;
    if (!site.active) {
      for (const driver of database.drivers.filter((item) => item.site_id === site.id && item.status === "available")) {
        driver.status = "offline";
      }
    }
    record(database, currentAccount.email, "site_updated", `${site.active ? "Se reactivó" : "Se suspendió"} ${site.name}.`, site.id);
    return;
  }

  if (action === "resetSitePassword") {
    requireAdmin(currentAccount);
    const site = database.sites.find((item) => item.id === value(payload.id, 64));
    const password = String(payload.password || "");
    if (!site) throw new AppError("No encontramos ese sitio de taxis.", 404);
    if (password.length < 8) throw new AppError("La nueva contraseña del sitio debe tener al menos 8 caracteres.");
    const manager = database.users.find((user) => user.site_id === site.id && user.role === "site");
    if (!manager) throw new AppError("El sitio no tiene una cuenta operativa.", 404);
    manager.password_hash = hashPassword(password);
    record(database, currentAccount.email, "site_password_reset", `Se actualizó la contraseña de ${site.name}.`, site.id);
    return;
  }

  if (action === "updateSiteSettings") {
    const site = database.sites.find((item) => item.id === value(payload.siteId || currentAccount.site_id, 64));
    if (!site) throw new AppError("No encontramos ese sitio de taxis.", 404);
    requireSiteOrAdmin(database, currentAccount, site.id);
    site.eta_default_minutes = Math.max(1, Math.min(120, Math.round(number(payload.etaMinutes, site.eta_default_minutes))));
    site.phone = value(payload.phone ?? site.phone, 20).replace(/[^\d+\s()-]/g, "");
    site.address = value(payload.address ?? site.address, 160);
    if (currentAccount.role === "admin") {
      site.dispatch_start = validTime(payload.dispatchStart, site.dispatch_start || database.settings.site_dispatch_start);
      site.dispatch_end = validTime(payload.dispatchEnd, site.dispatch_end || database.settings.site_dispatch_end);
      site.base_lat = optionalCoordinate(payload.baseLat ?? site.base_lat, 90);
      site.base_lng = optionalCoordinate(payload.baseLng ?? site.base_lng, 180);
      if (payload.sitePhotoKey) {
        const key = value(payload.sitePhotoKey, 80);
        if (!/^site\/[a-f0-9-]{36}\.(jpg|png|webp)$/.test(key)) throw new AppError("La fotografía del sitio no es válida.");
        site.photo_key = key;
      }
    }
    record(database, currentAccount.email, "site_settings", `Se actualizó la operación de ${site.name}.`, site.id);
    return;
  }

  if (action === "saveTariff") {
    requireAdmin(currentAccount);
    const normalized = normalizedTariff(payload, database.settings);
    const id = value(payload.id, 64);
    const existing = id ? database.tariffs.find((item) => item.id === id) : null;
    const duplicate = database.tariffs.find((item) => item.id !== id && samePlace(item.town, normalized.town) &&
      samePlace(item.origin, normalized.origin) && samePlace(item.destination, normalized.destination));
    if (duplicate) throw new AppError("Ya existe una tarifa para esa localidad, origen y destino.", 409);
    if (existing) Object.assign(existing, normalized, { updated_at: date() });
    else database.tariffs.push({ id: randomUUID(), ...normalized, active: true, created_at: date(), updated_at: date() });
    record(database, currentAccount.email, "tariff_saved", `Se guardó la tarifa ${normalized.town}: ${normalized.origin} → ${normalized.destination}.`);
    return;
  }

  if (action === "importTariffs") {
    requireAdmin(currentAccount);
    if (!Array.isArray(payload.rows) || !payload.rows.length || payload.rows.length > 1_000) {
      throw new AppError("El CSV debe incluir de 1 a 1,000 tarifas.");
    }
    let created = 0;
    let updated = 0;
    for (let index = 0; index < payload.rows.length; index++) {
      let normalized;
      try {
        normalized = normalizedTariff(payload.rows[index], database.settings);
      } catch (error) {
        throw new AppError(`Fila ${index + 2} del CSV: ${error.message}`);
      }
      const existing = database.tariffs.find((item) => samePlace(item.town, normalized.town) &&
        samePlace(item.origin, normalized.origin) && samePlace(item.destination, normalized.destination));
      if (existing) {
        Object.assign(existing, normalized, { active: true, updated_at: date() });
        updated++;
      } else {
        database.tariffs.push({ id: randomUUID(), ...normalized, active: true, created_at: date(), updated_at: date() });
        created++;
      }
    }
    record(database, currentAccount.email, "tariffs_imported", `Se importaron ${created} tarifas nuevas y se actualizaron ${updated}.`);
    return { created, updated };
  }

  if (action === "toggleTariff") {
    requireAdmin(currentAccount);
    const tariff = database.tariffs.find((item) => item.id === value(payload.id, 64));
    if (!tariff) throw new AppError("No encontramos esa tarifa.", 404);
    tariff.active = !tariff.active;
    tariff.updated_at = date();
    record(database, currentAccount.email, "tariff_status", `Se ${tariff.active ? "activó" : "suspendió"} el destino ${tariff.town} → ${tariff.destination}.`, tariff.id);
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
    const siteId = value(payload.siteId, 64);
    const unitNumber = value(payload.unitNumber, 20).toUpperCase();
    const plate = value(payload.plate, 18).toUpperCase();
    const vehicle = value(payload.vehicle, 90);
    const password = String(payload.password || "");
    const licenseNumber = value(payload.licenseNumber, 40);
    const permitNumber = value(payload.permitNumber, 40);
    const insurancePolicy = value(payload.insurancePolicy, 60);
    const insuranceExpiration = value(payload.insuranceExpiration, 10);

    if (name.length < 3 || !validEmail(accountEmail) || phone.replace(/\D/g, "").length < 8 || !unionId || !siteId || !unitNumber || !plate || !vehicle || password.length < 8) {
      throw new AppError("Completa nombre, correo, teléfono, sindicato, sitio, unidad, placas, vehículo y una contraseña de al menos 8 caracteres.");
    }
    if (!licenseNumber || !permitNumber) throw new AppError("Debes registrar la licencia del conductor y la concesión o permiso de la unidad.");
    if (database.settings.insurance_required && (!insurancePolicy || !/^\d{4}-\d{2}-\d{2}$/.test(insuranceExpiration) || insuranceExpiration < date().slice(0, 10))) {
      throw new AppError("La unidad necesita una póliza de responsabilidad civil vigente y su fecha de vencimiento.");
    }
    if (payload.driverConsent !== true) throw new AppError("Confirma que el taxista autorizó el uso de sus datos e imágenes y que revisaste su documentación.");
    if (database.users.some((item) => item.email === accountEmail)) throw new AppError("Ese correo ya tiene una cuenta registrada.", 409);
    if (database.drivers.some((item) => item.unit_number === unitNumber)) throw new AppError("Ya existe una unidad con ese número.", 409);
    if (!database.unions.some((item) => item.id === unionId && item.active)) throw new AppError("Selecciona un sindicato activo.");
    if (groupId && !database.groups.some((item) => item.id === groupId && item.parent_id === unionId && item.active)) {
      throw new AppError("El grupo seleccionado no pertenece a ese sindicato.");
    }
    const assignedSite = database.sites.find((site) => site.id === siteId && site.active);
    if (!assignedSite) throw new AppError("Selecciona un sitio autorizado y activo.");
    if (assignedSite.union_id && assignedSite.union_id !== unionId) throw new AppError("El sitio elegido pertenece a otro sindicato.");
    const driverPhotoKey = value(payload.driverPhotoKey, 80);
    const vehiclePhotoKey = value(payload.vehiclePhotoKey, 80);
    if (!/^driver\/[a-f0-9-]{36}\.(jpg|png|webp)$/.test(driverPhotoKey)) throw new AppError("La fotografía del taxista es obligatoria.");
    if (!/^vehicle\/[a-f0-9-]{36}\.(jpg|png|webp)$/.test(vehiclePhotoKey)) throw new AppError("La fotografía del taxi es obligatoria.");

    const driver = {
      id: randomUUID(), name, email: accountEmail, phone, union_id: unionId, group_id: groupId || null, site_id: siteId,
      unit_number: unitNumber, plate, vehicle, vehicle_color: value(payload.vehicleColor, 40) || "Blanco",
      license_number: licenseNumber, permit_number: permitNumber,
      insurance_policy: insurancePolicy, insurance_expiration: insuranceExpiration,
      driver_photo_key: driverPhotoKey, vehicle_photo_key: vehiclePhotoKey,
      consent_recorded_at: date(), consent_recorded_by: currentAccount.email,
      zone: value(payload.zone, 80) || "Turicato centro", status: "offline", verified: true, active: true,
      shift_start: validTime(payload.shiftStart, "06:00"), shift_end: validTime(payload.shiftEnd, "22:00"),
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
    const driver = database.drivers.find((item) => item.id === value(payload.id, 64));
    if (!driver) throw new AppError("No encontramos a ese taxista.", 404);
    requireSiteOrAdmin(database, currentAccount, driver.site_id);
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

  if (action === "updateDriverSchedule") {
    const driver = database.drivers.find((item) => item.id === value(payload.driverId, 64));
    if (!driver || (currentAccount.role !== "admin" && !(currentAccount.role === "driver" && driver.email === currentAccount.email))) {
      throw new AppError("Solo el propio taxista o la administración pueden modificar este horario.", 403);
    }
    driver.shift_start = validTime(payload.shiftStart, driver.shift_start || "06:00");
    driver.shift_end = validTime(payload.shiftEnd, driver.shift_end || "22:00");
    record(database, currentAccount.email, "driver_schedule", `La unidad ${driver.unit_number} estableció horario ${driver.shift_start}–${driver.shift_end}.`, driver.id);
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

  if (action === "updateDriverDocuments") {
    requireAdmin(currentAccount);
    const driver = database.drivers.find((item) => item.id === value(payload.id, 64));
    if (!driver) throw new AppError("No encontramos a ese taxista.", 404);
    const siteId = value(payload.siteId || driver.site_id, 64);
    const site = database.sites.find((item) => item.id === siteId && item.active);
    if (!site) throw new AppError("Selecciona un sitio activo para la unidad.");
    if (site.union_id && site.union_id !== driver.union_id) throw new AppError("Ese sitio no pertenece al sindicato del conductor.");
    const licenseNumber = value(payload.licenseNumber || driver.license_number, 40);
    const permitNumber = value(payload.permitNumber || driver.permit_number, 40);
    const insurancePolicy = value(payload.insurancePolicy || driver.insurance_policy, 60);
    const insuranceExpiration = value(payload.insuranceExpiration || driver.insurance_expiration, 10);
    if (!licenseNumber || !permitNumber) throw new AppError("La licencia y el permiso o concesión son obligatorios.");
    if (database.settings.insurance_required && (!insurancePolicy || !/^\d{4}-\d{2}-\d{2}$/.test(insuranceExpiration) || insuranceExpiration < date().slice(0, 10))) {
      throw new AppError("Debes registrar una póliza vigente de responsabilidad civil.");
    }
    driver.site_id = siteId;
    driver.license_number = licenseNumber;
    driver.permit_number = permitNumber;
    driver.insurance_policy = insurancePolicy;
    driver.insurance_expiration = insuranceExpiration;
    if (payload.driverPhotoKey) {
      const key = value(payload.driverPhotoKey, 80);
      if (!/^driver\/[a-f0-9-]{36}\.(jpg|png|webp)$/.test(key)) throw new AppError("La fotografía del taxista no es válida.");
      driver.driver_photo_key = key;
    }
    if (payload.vehiclePhotoKey) {
      const key = value(payload.vehiclePhotoKey, 80);
      if (!/^vehicle\/[a-f0-9-]{36}\.(jpg|png|webp)$/.test(key)) throw new AppError("La fotografía del vehículo no es válida.");
      driver.vehicle_photo_key = key;
    }
    record(database, currentAccount.email, "driver_documents", `Se actualizaron fotos y documentos de la unidad ${driver.unit_number}.`, driver.id);
    return;
  }

  if (action === "setDriverStatus") {
    if (!["admin", "driver", "site"].includes(currentAccount.role)) throw new AppError("Acceso exclusivo de operadores autorizados.", 403);
    const driver = database.drivers.find((item) => item.id === value(payload.driverId, 64));
    if (!driver?.active || !driver.verified || (currentAccount.role === "driver" && driver.email !== currentAccount.email) ||
      (currentAccount.role === "site" && driver.site_id !== currentAccount.site_id)) {
      throw new AppError("No puedes modificar esta unidad.", 403);
    }
    const next = payload.status === "available" ? "available" : "offline";
    if (next === "available" && !driverOrganization(database, driver).operational) {
      throw new AppError("La unidad requiere sitio activo, sindicato vigente, licencia, concesión y póliza de seguro no vencida.");
    }
    if (next === "offline" && database.rides.some((ride) => ride.driver_id === driver.id && ["accepted", "arrived", "in_progress"].includes(ride.status))) {
      throw new AppError("Primero termina el viaje que tienes en curso.", 409);
    }
    driver.status = next;
    record(database, currentAccount.email, "driver_status", `La unidad ${driver.unit_number} cambió a ${next === "available" ? "disponible" : "no visible"}.`, driver.id);
    return;
  }

  if (action === "createRide") {
    if (!["admin", "passenger"].includes(currentAccount.role)) throw new AppError("Solo los pasajeros pueden solicitar viajes.", 403);
    if (!database.settings.service_enabled) throw new AppError("El servicio está temporalmente en pausa.", 409);
    if (currentAccount.role === "passenger" && (!currentAccount.privacy_accepted_at || !currentAccount.terms_accepted_at || currentAccount.legal_version !== LEGAL_VERSION)) {
      throw new AppError("Antes de solicitar un taxi, revisa y acepta el aviso de privacidad y los términos actualizados.", 403);
    }
    if (database.rides.some((ride) => ride.passenger_email === currentAccount.email && ACTIVE_RIDES.has(ride.status))) {
      throw new AppError("Ya tienes un viaje en curso.", 409);
    }
    const site = database.sites.find((item) => item.id === value(payload.siteId, 64) && item.active);
    if (!site) throw new AppError("Selecciona un sitio de taxis autorizado para tu localidad.");
    if (currentAccount.role === "passenger" && !currentAccount.profile_photo_key) {
      throw new AppError("Completa primero la fotografía obligatoria de tu perfil.");
    }
    const tariff = database.tariffs.find((item) => item.id === value(payload.tariffId, 64) && item.active && samePlace(item.town, site.town));
    const specialDestination = value(payload.specialDestination, 110);
    if (!tariff && specialDestination.length < 3) throw new AppError("Selecciona un destino recomendado o escribe una salida especial.");
    const pickupLabel = value(payload.pickupLabel, 120);
    const destinationLabel = tariff?.destination || specialDestination;
    const pickupLat = number(payload.pickupLat, NaN);
    const pickupLng = number(payload.pickupLng, NaN);
    if (pickupLabel.length < 3 || destinationLabel.length < 3 || ![pickupLat, pickupLng].every(Number.isFinite) ||
      Math.abs(pickupLat) > 90 || Math.abs(pickupLng) > 180) {
      throw new AppError("Marca correctamente tu ubicación GPS de recogida y selecciona un destino autorizado.");
    }
    if (payload.safetyAccepted !== true) throw new AppError("Confirma que leíste las medidas básicas de seguridad del viaje.");
    if (site.base_lat !== null && site.base_lng !== null && site.base_lat !== undefined && site.base_lng !== undefined &&
      metersBetween(pickupLat, pickupLng, site.base_lat, site.base_lng) < database.settings.site_exclusion_meters) {
      throw new AppError("Esta aplicación se usa para recoger pasajeros fuera de la base; si estás en el sitio, solicita la unidad directamente.");
    }
    const adults = Math.max(1, Math.round(number(payload.adultPassengers ?? payload.passengers, 1)));
    const children = Math.max(0, Math.round(number(payload.childPassengers, 0)));
    if (adults + children > 4) throw new AppError("Todas las personas, incluidos menores, ocupan una plaza; no excedas cuatro pasajeros.");
    if (children && payload.childSafetyAccepted !== true) {
      throw new AppError("Confirma que los menores viajarán en el asiento trasero, con cinturón o sistema de retención apropiado; nunca en las piernas.");
    }
    const seniorPassengers = Math.max(0, Math.min(adults, Math.round(number(payload.seniorPassengers, currentAccount.senior_discount_eligible ? 1 : 0))));
    const studentPassengers = Math.max(0, Math.min(adults - seniorPassengers, Math.round(number(payload.studentPassengers, 0))));
    const priceMode = tariff?.price_mode || "person";
    const unitFare = tariff ? number(tariff.service_fare, 0) : database.settings.special_max_per_person;
    const serviceFare = Math.round(unitFare * (priceMode === "person" ? adults : 1) * 100) / 100;
    const pickupFee = number(tariff?.pickup_fee, database.settings.pickup_fee);
    const seniorDiscount = database.settings.discounts_authorized ? seniorPassengers * database.settings.senior_discount : 0;
    const studentDiscount = database.settings.discounts_authorized ? studentPassengers * number(tariff?.student_discount, database.settings.student_discount) : 0;
    if (database.settings.discounts_authorized && unitFare > 0 && priceMode === "person") {
      const individualDiscounts = [seniorPassengers ? database.settings.senior_discount : 0, studentPassengers ? number(tariff?.student_discount, database.settings.student_discount) : 0].filter(Boolean);
      if (individualDiscounts.some((amount) => amount + 0.001 < unitFare * .1 || amount - 0.001 > unitFare * .5)) {
        throw new AppError("El descuento configurado no está dentro del rango preferencial permitido para esta tarifa; solicita revisión de la administración.");
      }
    }
    const discount = Math.min(serviceFare, Math.round((seniorDiscount + studentDiscount) * 100) / 100);
    const fare = Math.round((serviceFare + pickupFee - discount) * 100) / 100;
    const pickupPhotoKey = value(payload.pickupPhotoKey, 80);
    if (pickupPhotoKey && !/^pickup\/[a-f0-9-]{36}\.(jpg|png|webp)$/.test(pickupPhotoKey)) throw new AppError("La fotografía de la fachada no es válida.");
    const ride = {
      id: randomUUID(), folio: `TUR-${Date.now().toString().slice(-6)}${randomInt(10)}`,
      passenger_email: currentAccount.email, passenger_name: currentAccount.name, passenger_phone: currentAccount.phone,
      driver_id: null, site_id: site.id, site_name: site.name, tariff_id: tariff?.id || null,
      pickup_label: pickupLabel, pickup_lat: pickupLat, pickup_lng: pickupLng,
      pickup_photo_key: pickupPhotoKey,
      destination_label: destinationLabel, destination_lat: tariff?.destination_lat ?? null, destination_lng: tariff?.destination_lng ?? null,
      arrival_point: tariff?.arrival_point || `Punto acordado en ${destinationLabel}`,
      origin_zone: tariff?.origin || site.town, service_fare: serviceFare, pickup_fee: pickupFee,
      price_mode: priceMode, unit_fare: unitFare, special_route: !tariff, price_requires_confirmation: !tariff,
      discount_amount: discount, senior_discount: seniorDiscount, student_discount: studentDiscount,
      distance_km: null, estimated_fare: fare, final_fare: null, status: "requested",
      eta_minutes: tariff?.eta_minutes || site.eta_default_minutes, eta_assigned_at: null, assigned_by: null,
      payment_method: "cash", passengers: adults + children, adult_passengers: adults,
      child_passengers: children, senior_passengers: seniorPassengers, student_passengers: studentPassengers,
      child_tariff_max_age: database.settings.child_free_max_age,
      notes: value(payload.notes, 240), security_code: String(randomInt(1000, 10000)), rating: null,
      safety_accepted_at: date(), route_events: [],
      created_at: date(), updated_at: date(), accepted_at: null, completed_at: null,
    };
    routeEvent(ride, currentAccount.email, "requested", `Ubicación de recogida registrada una sola vez; sitio ${site.name}.`);
    database.rides.unshift(ride);
    record(database, currentAccount.email, "ride_requested", `${site.name}: se solicitó ${ride.folio}, ${pickupLabel} → ${destinationLabel}.`, ride.id);
    return { id: ride.id, folio: ride.folio };
  }

  if (action === "acceptRide") {
    if (!["admin", "site", "driver"].includes(currentAccount.role)) throw new AppError("Solo operadores autorizados pueden tomar solicitudes.", 403);
    const ride = database.rides.find((item) => item.id === value(payload.rideId, 64));
    const driver = currentAccount.role === "driver" ? database.drivers.find((item) => item.email === currentAccount.email) :
      database.drivers.find((item) => item.id === value(payload.driverId, 64));
    if (!ride || ride.status !== "requested") throw new AppError("Otro taxista ya aceptó este servicio.", 409);
    if (ride.price_requires_confirmation) {
      throw new AppError("El sitio responsable debe confirmar primero el precio autorizado de esta salida especial.", 409);
    }
    if (currentAccount.role === "site" && ride.site_id !== currentAccount.site_id) {
      throw new AppError("Este servicio pertenece a otro sitio de taxis.", 403);
    }
    if (!driver?.active || !driver.verified || driver.status !== "available" || !driverOrganization(database, driver).operational ||
      driver.site_id !== ride.site_id) {
      throw new AppError("La unidad debe estar disponible, asegurada, autorizada y pertenecer al mismo sitio.", 409);
    }
    if (currentAccount.role === "driver" && !database.settings.allow_driver_claim) {
      throw new AppError("La administración desactivó temporalmente la toma directa de solicitudes.", 403);
    }
    if (currentAccount.role === "site") {
      const site = database.sites.find((item) => item.id === ride.site_id);
      if (!withinSchedule(site.dispatch_start || database.settings.site_dispatch_start, site.dispatch_end || database.settings.site_dispatch_end)) {
        throw new AppError("El control del sitio está fuera del horario autorizado; un taxista disponible puede tomar la solicitud.", 403);
      }
    }
    ride.driver_id = driver.id;
    ride.status = "accepted";
    ride.accepted_at = date();
    ride.updated_at = ride.accepted_at;
    ride.assigned_by = currentAccount.email;
    ride.eta_minutes = Math.max(1, Math.min(180, Math.round(number(payload.etaMinutes, ride.eta_minutes || database.settings.default_eta_minutes))));
    ride.eta_assigned_at = ride.accepted_at;
    driver.status = "busy";
    const mode = currentAccount.role === "driver" ? (payload.passingBy ? "tomó la solicitud por encontrarse de paso" : "tomó directamente la solicitud") : "asignó la unidad";
    routeEvent(ride, currentAccount.email, "assigned", `${mode}; unidad ${driver.unit_number}; llegada estimada en ${ride.eta_minutes} minutos.`);
    record(database, currentAccount.email, "ride_accepted", `${currentAccount.role === "driver" ? "El taxista" : "El sitio"} ${mode} ${driver.unit_number} a ${ride.folio}; llegada en ${ride.eta_minutes} min.`, ride.id);
    return;
  }

  if (action === "confirmSpecialFare") {
    const ride = database.rides.find((item) => item.id === value(payload.rideId, 64));
    if (!ride || !ride.special_route || ride.status !== "requested") throw new AppError("Selecciona una salida especial pendiente de asignación.", 409);
    requireSiteOrAdmin(database, currentAccount, ride.site_id);
    const perPerson = number(payload.perPerson, NaN);
    if (!Number.isFinite(perPerson) || perPerson < 0 || perPerson > database.settings.special_max_per_person) {
      throw new AppError("El importe por persona no puede superar el máximo configurado y debe estar legalmente autorizado.");
    }
    ride.unit_fare = Math.round(perPerson * 100) / 100;
    ride.service_fare = Math.round(ride.unit_fare * ride.adult_passengers * 100) / 100;
    ride.discount_amount = Math.min(ride.service_fare, number(ride.discount_amount, 0));
    ride.estimated_fare = Math.round((ride.service_fare + ride.pickup_fee - ride.discount_amount) * 100) / 100;
    ride.price_requires_confirmation = false;
    ride.price_confirmed_by = currentAccount.email;
    ride.updated_at = date();
    routeEvent(ride, currentAccount.email, "special_price", `Salida especial confirmada: ${ride.unit_fare} por persona.`);
    record(database, currentAccount.email, "special_fare_confirmed", `Se confirmó ${ride.unit_fare} por persona para ${ride.folio}.`, ride.id);
    return;
  }

  if (action === "updateRideEta") {
    const ride = database.rides.find((item) => item.id === value(payload.rideId, 64));
    if (!ride) throw new AppError("No encontramos ese servicio.", 404);
    requireSiteOrAdmin(database, currentAccount, ride.site_id);
    if (!["requested", "accepted", "arrived"].includes(ride.status)) throw new AppError("El tiempo de llegada ya no puede actualizarse.", 409);
    ride.eta_minutes = Math.max(1, Math.min(180, Math.round(number(payload.etaMinutes, ride.eta_minutes))));
    ride.eta_assigned_at = date();
    ride.updated_at = ride.eta_assigned_at;
    routeEvent(ride, currentAccount.email, "eta_updated", `Nuevo tiempo estimado: ${ride.eta_minutes} minutos.`);
    record(database, currentAccount.email, "eta_updated", `Se informó una llegada de ${ride.eta_minutes} minutos para ${ride.folio}.`, ride.id);
    return;
  }

  if (action === "advanceRide") {
    if (!["admin", "driver", "site"].includes(currentAccount.role)) throw new AppError("Acceso exclusivo de operadores autorizados.", 403);
    const ride = database.rides.find((item) => item.id === value(payload.rideId, 64));
    const driver = ride?.driver_id ? database.drivers.find((item) => item.id === ride.driver_id) : null;
    if (!ride || !driver || (currentAccount.role === "driver" && driver.email !== currentAccount.email) ||
      (currentAccount.role === "site" && ride.site_id !== currentAccount.site_id)) throw new AppError("Este viaje corresponde a otra unidad o sitio.", 403);
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
    routeEvent(ride, currentAccount.email, next, messages[next]);
    record(database, currentAccount.email, "ride_updated", messages[next], ride.id);
    return;
  }

  if (action === "cancelRide") {
    const ride = database.rides.find((item) => item.id === value(payload.rideId, 64));
    if (!ride) throw new AppError("No encontramos ese viaje.", 404);
    const driver = ride.driver_id ? database.drivers.find((item) => item.id === ride.driver_id) : null;
    if (currentAccount.role !== "admin" && ride.passenger_email !== currentAccount.email && driver?.email !== currentAccount.email &&
      !(currentAccount.role === "site" && currentAccount.site_id === ride.site_id)) {
      throw new AppError("No puedes cancelar este viaje.", 403);
    }
    if (!["requested", "accepted", "arrived"].includes(ride.status)) throw new AppError("Este viaje ya no puede cancelarse.", 409);
    ride.status = "cancelled";
    ride.updated_at = date();
    if (driver?.active) driver.status = "available";
    routeEvent(ride, currentAccount.email, "cancelled", "Servicio cancelado sin rastreo continuo.");
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
    record(database, currentAccount.email, "ride_rated", `Se calificó el servicio ${ride.folio} con ${ride.rating} estrellas.`, ride.id);
    return;
  }

  if (action === "createReport") {
    if (currentAccount.role !== "passenger") throw new AppError("Solo la persona usuaria puede reportar su propio servicio.", 403);
    const ride = database.rides.find((item) => item.id === value(payload.rideId, 64) && item.passenger_email === currentAccount.email && item.driver_id);
    if (!ride) throw new AppError("Selecciona un servicio asignado de tu propio historial.", 403);
    const category = value(payload.category, 40);
    if (!["speeding", "dangerous_overtake", "unsafe_driving", "mistreatment", "overcharge", "vehicle", "suggestion", "other"].includes(category)) {
      throw new AppError("Selecciona el motivo del comentario o reporte.");
    }
    const details = value(payload.details, 1200);
    if (details.length < 12) throw new AppError("Describe lo ocurrido con al menos 12 caracteres.");
    if (database.reports.some((item) => item.ride_id === ride.id && item.category === category && item.status !== "resolved")) {
      throw new AppError("Ya existe un reporte pendiente con este mismo motivo para el servicio.", 409);
    }
    const report = {
      id: randomUUID(), ride_id: ride.id, folio: ride.folio, site_id: ride.site_id, driver_id: ride.driver_id,
      passenger_email: currentAccount.email, passenger_name: currentAccount.name, category, details,
      severity: ["speeding", "dangerous_overtake", "unsafe_driving"].includes(category) ? "high" : "normal",
      status: "open", resolution: "", resolved_by: "", created_at: date(), updated_at: date(),
    };
    database.reports.unshift(report);
    record(database, currentAccount.email, "report_created", `Se registró reporte ${category} para ${ride.folio}; revisión del sitio requerida.`, ride.id);
    return { id: report.id };
  }

  if (action === "resolveReport") {
    const report = database.reports.find((item) => item.id === value(payload.reportId, 64));
    if (!report) throw new AppError("No encontramos ese reporte.", 404);
    requireSiteOrAdmin(database, currentAccount, report.site_id);
    const resolution = value(payload.resolution, 1000);
    if (resolution.length < 10) throw new AppError("Documenta la medida tomada y la respuesta al pasajero.");
    report.status = payload.status === "reviewing" ? "reviewing" : "resolved";
    report.resolution = resolution;
    report.resolved_by = currentAccount.email;
    report.updated_at = date();
    record(database, currentAccount.email, "report_updated", `Se ${report.status === "resolved" ? "resolvió" : "puso en revisión"} el reporte del servicio ${report.folio}.`, report.ride_id);
    return;
  }

  if (action === "purgeExpiredData") {
    requireAdmin(currentAccount);
    const retentionDays = database.settings.data_retention_days;
    const cutoff = Date.now() - retentionDays * 86_400_000;
    const originalRides = database.rides.length;
    const beforeRides = [...database.rides];
    const originalEvents = database.activity.length;
    const originalReports = database.reports.length;
    database.rides = database.rides.filter((ride) => {
      if (!["completed", "cancelled"].includes(ride.status) || ride.legal_hold === true) return true;
      if (database.reports.some((report) => report.ride_id === ride.id &&
        (report.status !== "resolved" || Date.parse(report.updated_at || report.created_at || "") >= cutoff))) return true;
      const stamp = Date.parse(ride.completed_at || ride.updated_at || ride.created_at || "");
      return !Number.isFinite(stamp) || stamp >= cutoff;
    });
    const retainedRides = new Set(database.rides.map((ride) => ride.id));
    const photosToDelete = beforeRides.filter((ride) => !retainedRides.has(ride.id) && ride.pickup_photo_key).map((ride) => ride.pickup_photo_key);
    database.reports = database.reports.filter((report) => retainedRides.has(report.ride_id) || report.status !== "resolved");
    database.activity = database.activity.filter((entry) => {
      const stamp = Date.parse(entry.created_at || entry.at || "");
      return !Number.isFinite(stamp) || stamp >= cutoff;
    });
    const removed = originalRides - database.rides.length;
    const activityRemoved = originalEvents - database.activity.length;
    const reportsRemoved = originalReports - database.reports.length;
    database.settings.last_purge_at = date();
    record(database, currentAccount.email, "retention_purge", `Se depuraron ${removed} servicios, ${reportsRemoved} reportes resueltos y ${activityRemoved} eventos vencidos.`, null);
    return { removed, reportsRemoved, activityRemoved, retentionDays, _photosToDelete: photosToDelete };
  }

  if (action === "saveSettings") {
    requireAdmin(currentAccount);
    database.settings = {
      ...database.settings,
      base_fare: Math.max(0, Math.min(2000, number(payload.baseFare, 35))),
      fare_per_km: Math.max(0, Math.min(1000, number(payload.farePerKm, 11))),
      minimum_fare: Math.max(0, Math.min(2000, number(payload.minimumFare, 45))),
      pickup_fee: Math.max(0, Math.min(5000, number(payload.pickupFee, database.settings.pickup_fee))),
      default_eta_minutes: Math.max(1, Math.min(120, Math.round(number(payload.defaultEtaMinutes, database.settings.default_eta_minutes)))),
      service_enabled: payload.serviceEnabled !== false,
      support_phone: value(payload.supportPhone, 20),
      service_area: value(payload.serviceArea, 90) || "Turicato, Michoacán",
      responsible_name: value(payload.responsibleName ?? database.settings.responsible_name, 130),
      responsible_address: value(payload.responsibleAddress ?? database.settings.responsible_address, 180),
      privacy_email: email(payload.privacyEmail ?? database.settings.privacy_email),
      incident_phone: value(payload.incidentPhone ?? database.settings.incident_phone, 20),
      data_retention_days: Math.max(30, Math.min(1825, Math.round(number(payload.retentionDays, database.settings.data_retention_days)))),
      pilot_mode: payload.pilotMode !== false,
      legal_review_confirmed: payload.legalReviewConfirmed === true,
      transport_authorization_confirmed: payload.transportAuthorizationConfirmed === true,
      insurance_required: payload.insuranceRequired !== false,
      senior_discount: Math.max(0, Math.min(500, number(payload.seniorDiscount, database.settings.senior_discount))),
      student_discount: Math.max(0, Math.min(500, number(payload.studentDiscount, database.settings.student_discount))),
      discounts_authorized: payload.discountsAuthorized === true,
      child_free_max_age: Math.max(0, Math.min(payload.childFareAuthorized === true ? 9 : 2, Math.round(number(payload.childFreeMaxAge, database.settings.child_free_max_age)))),
      child_fare_authorized: payload.childFareAuthorized === true,
      special_max_per_person: Math.max(1, Math.min(10_000, number(payload.specialMaxPerPerson, database.settings.special_max_per_person))),
      site_dispatch_start: validTime(payload.siteDispatchStart, database.settings.site_dispatch_start),
      site_dispatch_end: validTime(payload.siteDispatchEnd, database.settings.site_dispatch_end),
      site_exclusion_meters: Math.max(20, Math.min(500, Math.round(number(payload.siteExclusionMeters, database.settings.site_exclusion_meters)))),
      allow_driver_claim: payload.allowDriverClaim !== false,
    };
    if (database.settings.privacy_email && !validEmail(database.settings.privacy_email)) {
      throw new AppError("El correo para derechos de privacidad debe ser válido.");
    }
    if (!database.settings.pilot_mode && !legalReady(database.settings)) {
      throw new AppError("Antes de salir del modo piloto, completa los datos legales y confirma la revisión jurídica y de transporte.");
    }
    record(database, currentAccount.email, "settings_updated", "Se actualizó la configuración del servicio.");
    return;
  }

  throw new AppError("Acción no reconocida.", 400);
}

export default async function handler(request) {
  try {
    const configuration = requireConfiguration();
    const database = await ensureAdministrator(configuration);
    const address = new URL(request.url);

    if (request.method === "GET") {
      if (address.searchParams.get("public") === "legal") {
        return response({ ok: true, settings: publicLegalSettings(database.settings) });
      }
      const account = signedInAccount(request, database, configuration);
      if (address.searchParams.has("photo")) {
        if (!account) throw new AppError("Inicia sesión para consultar fotografías autorizadas.", 401);
        return await servePhoto(database, account, address.searchParams.get("photo") || "");
      }
      return account ? response(visibleState(database, account)) : response({ authenticated: false });
    }

    if (request.method !== "POST") return response({ error: "Método no permitido." }, 405);
    const origin = request.headers.get("origin");
    if (origin && origin !== new URL(request.url).origin) throw new AppError("Solicitud de origen no autorizado.", 403);
    if (!request.headers.get("content-type")?.toLowerCase().includes("application/json")) throw new AppError("El contenido debe enviarse como JSON.", 415);
    const contentLength = Number(request.headers.get("content-length") || 0);
    if (contentLength > 1_500_000) throw new AppError("La solicitud es demasiado grande.", 413);

    const payload = await request.json();
    const action = value(payload.action, 40);

    if (action === "login") return await login(request, payload, configuration, database);
    if (action === "registerPassenger") return await registerPassenger(request, payload, configuration);
    if (action === "logout") return response({ ok: true }, 200, { "Set-Cookie": cookie(request, "", 0) });

    const account = signedInAccount(request, database, configuration);
    if (!account) throw new AppError("Tu sesión venció. Inicia sesión nuevamente.", 401);

    if (action === "uploadPhoto") return await uploadPhoto(database, account, payload);

    const photoReference = action === "createRide" ? payload.pickupPhotoKey : action === "saveProfile" ? payload.profilePhotoKey : null;
    if (photoReference && account.role === "passenger") {
      const uploaded = await mediaStore().getWithMetadata(value(photoReference, 80), { type: "arrayBuffer", consistency: "strong" });
      if (!uploaded || uploaded.metadata?.uploadedBy !== account.email) {
        throw new AppError("La fotografía seleccionada no pertenece a tu cuenta.", 403);
      }
    }

    const saved = await transaction((current) => performAction(current, account, action, payload));
    const result = { ...(saved.result || {}) };
    const expiredPhotos = Array.isArray(result._photosToDelete) ? result._photosToDelete : [];
    delete result._photosToDelete;
    if (expiredPhotos.length) {
      const outcomes = await Promise.allSettled(expiredPhotos.map((key) => mediaStore().delete(key)));
      result.photosRemoved = outcomes.filter((item) => item.status === "fulfilled").length;
      if (result.photosRemoved !== expiredPhotos.length) {
        result.cleanupWarning = "Algunas fotografías requieren revisión manual de eliminación.";
      }
    }
    return response({ ok: true, ...result });
  } catch (error) {
    if (error instanceof AppError) return response({ error: error.message }, error.status);
    console.error("Taxi Turicato server error:", error);
    return response({ error: "No fue posible completar la operación. Inténtalo nuevamente." }, 500);
  }
}

export const config = { path: "/api/taxi" };

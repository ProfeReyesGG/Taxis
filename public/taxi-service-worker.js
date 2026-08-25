"use strict";

self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("push", (event) => {
  let payload = {};
  try { payload = event.data ? event.data.json() : {}; }
  catch { payload = { body: event.data ? event.data.text() : "Abre Taxi Turicato para consultar el aviso." }; }

  const title = payload.title || "Taxi Turicato";
  event.waitUntil(self.registration.showNotification(title, {
    body: payload.body || "Tienes una actualización de tu servicio.",
    icon: "/favicon.svg",
    badge: "/favicon.svg",
    tag: payload.tag || "taxi-turicato-aviso",
    data: {
      notificationId: payload.notificationId || "",
      targetPage: payload.targetPage || "notifications",
      url: "/",
    },
    requireInteraction: false,
  }));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const data = event.notification.data || {};
  const targetPage = data.targetPage || "notifications";
  const target = new URL(data.url || "/", self.location.origin);
  target.searchParams.set("aviso", targetPage);
  if (data.notificationId) target.searchParams.set("notificacion", data.notificationId);

  event.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((windows) => {
    const existing = windows.find((window) => new URL(window.url).origin === self.location.origin);
    if (existing) {
      existing.postMessage({ type: "taxi-notification-open", targetPage, notificationId: data.notificationId || "" });
      return existing.focus();
    }
    return self.clients.openWindow(target.toString());
  }));
});

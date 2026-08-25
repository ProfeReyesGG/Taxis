(()=>{
  "use strict";
  try{document.documentElement.dataset.theme=localStorage.getItem("taxi-turicato-theme")||(window.matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light")}catch(error){document.documentElement.dataset.theme="light"}
  const query=new URLSearchParams(window.location.search);
  const requestedSite=query.get("site");
  const endpoint="/api/taxi?public=legal"+(requestedSite?"&site="+encodeURIComponent(requestedSite):"");
  if(window.location.pathname.endsWith("/privacidad.html")){
    const add=(selector,tag,text)=>{
      const parent=document.querySelector(selector);
      if(!parent)return;
      const node=document.createElement(tag);node.textContent=text;parent.appendChild(node);
    };
    add("#apartado-3 ul","li","Notificaciones operativas, registro de lectura y, si autorizas avisos del dispositivo, una dirección técnica de suscripción cifrada y claves públicas necesarias para entregar Web Push.");
    add("#apartado-3 ul","li","Reportes privados elaborados por el taxista sobre un servicio propio, conteo de cancelaciones, hechos documentados, revisión humana del sitio y calificación interna no pública.");
    add("#apartado-6 ul","li","Avisar solicitudes, asignaciones, llegadas, cancelaciones y seguimiento de reportes; el permiso para avisos del dispositivo es opcional y revocable.");
    add("#apartado-10","p","Los reportes privados sobre pasajeros solo son accesibles para el taxista que atendió ese servicio, el sitio directamente responsable y la administración maestra. No se publican, no se muestran a otras bases, no son visibles al pasajero en la interfaz y no se comparten con otros conductores.");
    add("#apartado-12","p","Si activas voluntariamente las notificaciones del sistema, se utiliza un trabajador de servicio y una suscripción cifrada del navegador. Puedes desactivarla en cualquier momento; no se usa para seguimiento de ubicación, publicidad ni identificación entre sitios.");
    add("#apartado-16","p","Las cancelaciones se contabilizan como hechos operativos. Toda observación o calificación interna de un pasajero requiere revisión humana del sitio o de la administración; no debe utilizarse como acusación pública ni producir suspensiones o negativas automáticas.");
    const date=document.querySelector(".legal-date");
    if(date)date.textContent="Última actualización: 25 de agosto de 2026 · Versión 2026-08-25";
  }
  function fill(selector,values,attribute){
    document.querySelectorAll(selector).forEach(node=>{
      const key=node.getAttribute(attribute);
      const selected=values?.[key];
      if(selected!==undefined&&selected!==null&&String(selected).trim())node.textContent=String(selected);
    });
  }
  function bind(prefix,initial={}){
    document.querySelectorAll(`[data-${prefix}-input]`).forEach(input=>{
      const key=input.getAttribute(`data-${prefix}-input`);
      if(initial[key]!==undefined&&initial[key]!==null)input.value=String(initial[key]);
      input.addEventListener("input",()=>{
        const values={};values[key]=input.value.trim()||"Pendiente de completar antes de firmar";
        fill(`[data-${prefix}]`,values,`data-${prefix}`);
      });
    });
  }
  document.querySelectorAll("[data-legal-print]").forEach(button=>button.addEventListener("click",()=>window.print()));
  bind("site");bind("contract");
  fetch(endpoint,{credentials:"same-origin",cache:"no-store"}).then(async response=>{
    const result=await response.json();
    if(!response.ok)throw new Error(result.error||"No se pudo cargar el acuerdo personalizado.");
    return result;
  }).then(result=>{
    const data=result.settings||{};fill("[data-legal]",data,"data-legal");
    if(result.site){fill("[data-site]",result.site,"data-site");bind("site",result.site);}
    const warning=document.getElementById("legal-pilot-warning");
    if(warning&&data.legal_ready){warning.classList.add("is-ready");warning.textContent="Información del responsable configurada. Conserva evidencia de permisos, seguros, revisión jurídica y autorizaciones vigentes."}
    else if(warning){warning.textContent="MODO PILOTO: faltan identidad o domicilio del responsable, contacto de privacidad, revisión jurídica o confirmación ante la autoridad de transporte."}
  }).catch(error=>{
    const warning=document.getElementById("legal-pilot-warning");
    if(warning&&requestedSite)warning.textContent=error.message+" Abre este documento desde la cuenta del sitio o la administración maestra.";
  });
})();

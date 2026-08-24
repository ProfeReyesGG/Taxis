(()=>{
  "use strict";
  const query=new URLSearchParams(window.location.search);
  const requestedSite=query.get("site");
  const endpoint="/api/taxi?public=legal"+(requestedSite?"&site="+encodeURIComponent(requestedSite):"");
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

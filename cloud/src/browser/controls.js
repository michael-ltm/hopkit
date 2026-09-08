// Native form values remain available to FormData; all visible widgets and
// validation messages are rendered by SSHM, including keyboard/focus behavior.
let closePicker=()=>{},closeTooltip=()=>{},sequence=0;
const enhanced=new WeakMap();
export function closeControls(){closePicker();closeTooltip();}
function text(tag,cls,value){const e=document.createElement(tag);e.className=cls;e.textContent=value;return e;}
function enhance(select){
 if(enhanced.has(select)){enhanced.get(select)();return;}
 const wrap=document.createElement('span');wrap.className='select-control';select.before(wrap);wrap.append(select);select.hidden=true;select.tabIndex=-1;
 const button=text('button','select-trigger','');button.type='button';button.setAttribute('aria-haspopup','listbox');button.setAttribute('aria-expanded','false');
 const label=text('span','select-label',''),chevron=text('span','select-chevron','⌄');chevron.setAttribute('aria-hidden','true');button.append(label,chevron);wrap.append(button);
 const sync=()=>{const value=select.selectedOptions[0]?.textContent||'请选择';if(label.textContent!==value)label.textContent=value;button.disabled=select.disabled;const title=select.getAttribute('aria-label')||select.labels?.[0]?.firstChild?.textContent?.trim()||'选择';button.setAttribute('aria-label',title+'：'+value);};
 enhanced.set(select,sync);sync();
 button.onclick=()=>{
  if(button.getAttribute('aria-expanded')==='true'){closePicker();return;}closePicker();
  const popup=document.createElement('div');popup.className='select-options';popup.id='select-options-'+(++sequence);popup.setAttribute('role','listbox');popup.setAttribute('aria-label',button.getAttribute('aria-label'));popup.popover='manual';(select.closest('dialog')||document.body).append(popup);
  button.setAttribute('aria-controls',popup.id);button.setAttribute('aria-expanded','true');const options=[];
  const close=(focus=false)=>{if(!popup.isConnected)return;popup.remove();button.setAttribute('aria-expanded','false');button.removeAttribute('aria-controls');document.removeEventListener('pointerdown',outside,true);window.removeEventListener('resize',resize);document.removeEventListener('scroll',resize,true);if(focus&&button.isConnected)button.focus();};
  closePicker=()=>close(false);const outside=e=>{if(!popup.contains(e.target)&&!button.contains(e.target))close(false);};const resize=e=>{if(e?.type==='scroll'&&popup.contains(e.target))return;close(false);};
  for(const option of select.options){const b=text('button','select-option',option.textContent);b.type='button';b.setAttribute('role','option');b.setAttribute('aria-selected',String(option.selected));b.disabled=option.disabled;b.tabIndex=-1;b.onclick=()=>{select.value=option.value;sync();close(true);select.dispatchEvent(new Event('input',{bubbles:true}));select.dispatchEvent(new Event('change',{bubbles:true}));};popup.append(b);if(!b.disabled)options.push(b);}
  popup.showPopover();const rect=button.getBoundingClientRect();popup.style.width=Math.min(Math.max(rect.width,180),innerWidth-16)+'px';const height=Math.min(popup.scrollHeight,280,innerHeight-24);popup.style.maxHeight=height+'px';popup.style.left=Math.max(8,Math.min(rect.left,innerWidth-popup.offsetWidth-8))+'px';popup.style.top=(rect.bottom+height+8<innerHeight?rect.bottom+5:Math.max(8,rect.top-height-5))+'px';
  (options.find(b=>b.getAttribute('aria-selected')==='true')||options[0])?.focus();
  let search='',lastKey=0;
  popup.onkeydown=e=>{let index=options.indexOf(document.activeElement);if(['ArrowDown','ArrowUp','Home','End'].includes(e.key)){e.preventDefault();index=e.key==='Home'?0:e.key==='End'?options.length-1:(index+(e.key==='ArrowDown'?1:-1)+options.length)%options.length;options[index]?.focus();}else if(e.key==='Escape'){e.preventDefault();e.stopPropagation();close(true);}else if(e.key==='Tab'){close(true);}else if(e.key.length===1&&!e.ctrlKey&&!e.metaKey){search=Date.now()-lastKey>700?e.key:search+e.key;lastKey=Date.now();options.find(b=>b.textContent.toLowerCase().startsWith(search.toLowerCase()))?.focus();}};
  document.addEventListener('pointerdown',outside,true);window.addEventListener('resize',resize);document.addEventListener('scroll',resize,true);
 };
 button.onkeydown=e=>{if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();button.click();}};
 select.addEventListener('change',sync);select.form?.addEventListener('reset',()=>queueMicrotask(sync));
}
export function refreshControls(){for(const target of document.querySelectorAll("[title]")){if(target.title)target.dataset.hint=target.title;target.removeAttribute("title");}for(const s of document.querySelectorAll('select'))enhance(s);for(const form of document.forms)form.noValidate=true;for(const input of document.querySelectorAll('input[type=number]')){input.dataset.numeric='true';input.type='text';input.inputMode='numeric';}}
export async function confirmAction(title,message){
 closeControls();const d=document.createElement('dialog');d.className='confirm-dialog';const head=text('div','modal-head',''),h=text('h2','',title);h.id='confirm-'+(++sequence);d.setAttribute('aria-labelledby',h.id);head.append(h);const body=text('div','modal-body',''),p=text('p','',message),actions=text('div','modal-actions',''),cancel=text('button','','取消'),ok=text('button','danger','确认撤销');actions.append(cancel,ok);body.append(p,actions);d.append(head,body);document.body.append(d);
 return new Promise(resolve=>{let yes=false;cancel.onclick=()=>d.close();ok.onclick=()=>{yes=true;d.close();};d.onclose=()=>{d.remove();resolve(yes);};d.showModal();cancel.focus();});
}
export function installControls(){
 refreshControls();
 const hint=e=>{const target=e.target.closest?.('[data-hint]');closeTooltip();if(!target)return;let timer,tip;const prior=target.getAttribute('aria-describedby');closeTooltip=()=>{clearTimeout(timer);tip?.remove();if(prior)target.setAttribute('aria-describedby',prior);else target.removeAttribute('aria-describedby');};timer=setTimeout(()=>{if(!target.isConnected)return;tip=text('div','custom-tooltip',target.dataset.hint);tip.id='hint-'+(++sequence);tip.setAttribute('role','tooltip');tip.popover='manual';(target.closest('dialog')||document.body).append(tip);tip.showPopover();target.setAttribute('aria-describedby',tip.id);const r=target.getBoundingClientRect();tip.style.left=Math.max(8,Math.min(r.left,innerWidth-tip.offsetWidth-8))+'px';tip.style.top=(r.bottom+tip.offsetHeight+12<innerHeight?r.bottom+7:Math.max(8,r.top-tip.offsetHeight-7))+'px';},450);};
 document.addEventListener('pointerover',hint);document.addEventListener('focusin',hint);document.addEventListener('pointerout',()=>closeTooltip());document.addEventListener('focusout',()=>closeTooltip());document.addEventListener('pointerdown',()=>closeTooltip());document.addEventListener('scroll',()=>closeTooltip(),true);
 let queued=false;new MutationObserver(()=>{if(queued)return;queued=true;queueMicrotask(()=>{queued=false;refreshControls();});}).observe(document.body,{childList:true,subtree:true});
 document.addEventListener('submit',e=>{
  const f=e.target;if(!(f instanceof HTMLFormElement))return;
  f.querySelectorAll('.field-error').forEach(n=>n.remove());f.querySelectorAll('[aria-invalid]').forEach(n=>{n.removeAttribute('aria-invalid');n.removeAttribute('aria-errormessage');});
  for(const input of f.elements){if(input.disabled||input.type==='hidden'||!('validity' in input))continue;let error='';const value=input.value||'';
   if(input.required&&!value.trim())error='请填写此项。';else if(input.validity.patternMismatch)error='格式不正确，请按示例填写。';else if(input.minLength>0&&[...value].length<input.minLength&&value)error='至少需要 '+input.minLength+' 个字符。';else if(input.maxLength>0&&[...value].length>input.maxLength)error='最多 '+input.maxLength+' 个字符。';else if(input.dataset.numeric&&(!/^\d+$/.test(value)||Number(value)<Number(input.min||0)||Number(value)>Number(input.max||Number.MAX_SAFE_INTEGER)))error='请输入 '+input.min+'–'+input.max+' 之间的整数。';
   if(error){e.preventDefault();e.stopImmediatePropagation();input.setAttribute('aria-invalid','true');const msg=text('span','field-error',error);msg.id='field-error-'+(++sequence);msg.setAttribute('role','alert');input.setAttribute('aria-errormessage',msg.id);input.after(msg);if(input.tagName==='SELECT')input.parentElement.querySelector('button').focus();else input.focus();break;}
  }
 },true);
 document.addEventListener('keydown',e=>{if(e.key==='Escape')closeControls();});
}

// Exports only credentials explicitly attached to the current connection.
function entryFor(data,id){
 const entry=data?.entries?.[id];
 if(!entry||data.deleted?.[id]||data.conflicts?.[id])throw Error('连接已改变、存在冲突或保险库已锁定，请重新选择。');
 return entry;
}
export function exportableKeys(data,id){
 return [...new Set(entryFor(data,id).credentials||[])].filter(id=>data.credentials?.[id]?.kind==='key'&&data.credentials[id].key).map(id=>({id,fingerprint:data.credentials[id].fingerprint||id}));
}
export function exportKey(data,entryID,credentialID){
 const entry=entryFor(data,entryID);
 if(!exportableKeys(data,entryID).some(c=>c.id===credentialID))throw Error('所选连接没有这把私钥。');
 let bytes;
 try{bytes=Uint8Array.from(atob(data.credentials[credentialID].key),c=>c.charCodeAt(0));}catch{throw Error('私钥编码无效，未导出。');}
 const text=new TextDecoder().decode(bytes);
 if(!/^-----BEGIN ((?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY)-----\r?\n[\s\S]+\r?\n-----END \1-----[ \t]*\r?$/m.test(text)){bytes.fill(0);throw Error('凭据不是受支持的私钥文件，未导出。');}
 const alias=(entry.aliases?.[0]||'ssh-key').replace(/[^\p{L}\p{N}_-]/gu,'_').slice(0,100)||'ssh-key';
 return {filename:alias+'.key',bytes};
}
export function downloadKey(result){
 const url=URL.createObjectURL(new Blob([result.bytes],{type:'application/octet-stream'}));
 const link=document.createElement('a');
 try{link.href=url;link.download=result.filename;document.body.append(link);link.click();}
 finally{link.remove();result.bytes.fill(0);setTimeout(()=>URL.revokeObjectURL(url),1000);}
}

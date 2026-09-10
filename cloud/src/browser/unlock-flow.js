// Keeps only an action, never an unlock phrase or key. Cancellation invalidates
// the ticket held by an in-flight unlock so it cannot resume another action.
export function createUnlockFlow({isUnlocked,show}) {
 let pending=null,sequence=0;
 return {
  ticket:()=>pending?.id??null,
  cancel(){pending=null;sequence++;},
  async run(label,action){
   if(pending)return false;
   if(isUnlocked()){await action();return true;}
   pending={id:++sequence,action};show(label);return false;
  },
  async resume(ticket){
   if(!pending||pending.id!==ticket||!isUnlocked())return false;
   const {action}=pending;pending=null;
   await action();return true;
  }
 };
}

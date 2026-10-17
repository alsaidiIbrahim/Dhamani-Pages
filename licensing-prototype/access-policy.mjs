// Pure, offline-safe policy evaluator. No customer invoice data is transmitted.
export const DAY_MS=86400000;
export function licenseAccess(certificate, now, {clockRollbackToleranceMs=5*60000,latestObservedAt=null}={}){
 const readOnly={canRead:true,canExport:true,canCreate:false,canEdit:false};
 if(!certificate||typeof certificate!=='object')return {...readOnly,state:'activation_required'};
 const {verifiedAt,nextCheckAt,licenseType}=certificate;
 if(licenseType!=='perpetual_single_device'||!Number.isSafeInteger(verifiedAt)||!Number.isSafeInteger(nextCheckAt)||nextCheckAt-verifiedAt!==30*DAY_MS)return {...readOnly,state:'invalid_certificate'};
 if(!Number.isFinite(now))return {...readOnly,state:'invalid_clock'};
 if(Number.isFinite(latestObservedAt)&&now+clockRollbackToleranceMs<latestObservedAt)return {...readOnly,state:'clock_rollback'};
 if(now<verifiedAt-clockRollbackToleranceMs)return {...readOnly,state:'clock_rollback'};
 if(now>nextCheckAt)return {...readOnly,state:'verification_required'};
 const daysRemaining=Math.max(0,Math.ceil((nextCheckAt-now)/DAY_MS));
 return {canRead:true,canExport:true,canCreate:true,canEdit:true,state:daysRemaining<=3?'verification_soon':'active',daysRemaining};
}
export function verifiedLicenseAccess(signedCertificate,serverPublicKey,verifySignedCertificate,now,options){
 // Signature MUST be verified before trusting dates or permissions.
 let payload=null;
 try{payload=verifySignedCertificate(signedCertificate,serverPublicKey)}catch{}
 return licenseAccess(payload,now,options);
}

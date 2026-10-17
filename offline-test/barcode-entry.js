import { BrowserMultiFormatReader } from '@zxing/browser';
import { BarcodeFormat, DecodeHintType } from '@zxing/library';
const formats=[BarcodeFormat.QR_CODE,BarcodeFormat.CODE_128,BarcodeFormat.CODE_39,BarcodeFormat.EAN_13,BarcodeFormat.EAN_8,BarcodeFormat.UPC_A,BarcodeFormat.ITF,BarcodeFormat.DATA_MATRIX,BarcodeFormat.PDF_417];
const createReader=()=>new BrowserMultiFormatReader(new Map([[DecodeHintType.POSSIBLE_FORMATS,formats],[DecodeHintType.TRY_HARDER,true]]),200);
export async function decodeImage(file){
 const url=URL.createObjectURL(file);
 try{return (await createReader().decodeFromImageUrl(url)).getText()}
 finally{URL.revokeObjectURL(url)}
}
export async function startCamera(video,callback){
 const reader=createReader();
 const controls=await reader.decodeFromVideoDevice(undefined,video,(result,error)=>{
  if(result)callback(result.getText());
 });
 return controls;
}

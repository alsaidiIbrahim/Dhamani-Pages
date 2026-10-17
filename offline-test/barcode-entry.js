import { BrowserMultiFormatReader } from '@zxing/browser';
import { BarcodeFormat, DecodeHintType } from '@zxing/library';
export async function decodeImage(file) {
  const url=URL.createObjectURL(file);
  try {
    const reader=new BrowserMultiFormatReader(new Map([[DecodeHintType.POSSIBLE_FORMATS, [BarcodeFormat.QR_CODE,BarcodeFormat.CODE_128,BarcodeFormat.CODE_39,BarcodeFormat.EAN_13,BarcodeFormat.EAN_8,BarcodeFormat.UPC_A,BarcodeFormat.ITF,BarcodeFormat.DATA_MATRIX,BarcodeFormat.PDF_417]]]));
    const result=await reader.decodeFromImageUrl(url);
    return result.getText();
  } finally {URL.revokeObjectURL(url)}
}

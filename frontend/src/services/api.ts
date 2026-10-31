const API=import.meta.env.VITE_API_BASE_URL??'http://localhost:8000/api';

export class ApiError extends Error{
 constructor(public readonly status:number,message:string){super(message);this.name='ApiError'}
}

async function readResponse<T>(response:Response):Promise<T>{
 if(!response.ok){let details='';try{details=await response.text()}catch{};throw new ApiError(response.status,details||`${response.status} ${response.statusText}`)}
 return response.json() as Promise<T>;
}

export async function get<T>(path:string):Promise<T>{return readResponse<T>(await fetch(API+path))}
export async function post<T>(path:string,body?:any):Promise<T>{
 return readResponse<T>(await fetch(API+path,{method:'POST',headers:body?{'Content-Type':'application/json'}:undefined,body:body?JSON.stringify(body):undefined}));
}
export async function upload(file:File):Promise<{file:string;bytes:number}>{
 const form=new FormData();form.append('file',file);
 return readResponse(await fetch(API+'/ingest/upload',{method:'POST',body:form}));
}
export async function streamUpload(file:File,onProgress:(sent:number,total:number)=>void):Promise<{file:string;bytes:number;job_id:string;state:string;phase?:string;detection_state?:string;status_url:string}>{
 const chunkSize=4*1024*1024;let offset=0;
 const body=new ReadableStream<Uint8Array>({
  async pull(controller){
   if(offset>=file.size){controller.close();return}
   const next=await file.slice(offset,Math.min(file.size,offset+chunkSize)).arrayBuffer();
   offset+=next.byteLength;controller.enqueue(new Uint8Array(next));onProgress(offset,file.size);
   if(offset>=file.size)controller.close();
  }
 });
 const init={method:'POST',headers:{'Content-Type':'application/octet-stream','X-File-Name':encodeURIComponent(file.name),'X-File-Size':String(file.size)},body,duplex:'half'} as RequestInit & {duplex:'half'};
 return readResponse(await fetch(API+'/ingest/stream',init));
}
export async function startJob(source:{filename?:string;source_path?:string}):Promise<{job_id:string;state:string;status_url:string;resuming:boolean}>{
 return readResponse(await fetch(API+'/ingest/jobs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(source)}));
}
export {API};

export type Role = 'Viewer'|'Analyst'|'Operator'|'Approver'|'Executor'|'Auditor'
export type SourceMode = 'LIVE'|'HISTORICAL'|'ISOLATED'|'STAGING'|'TEST'
export interface AuthSession { username:string; roles:Role[]; expires_at:string; csrf_token:string }
export interface Capabilities { user_id:string; portal_admin:boolean; can_triage:boolean; can_read_notes:boolean; network_actions_enabled:false; context:'TEST'|'PORTAL' }
export interface Overlay { kind:'incident'|'alert'; object_id:string; stream_id:string; execution_mode:SourceMode; review_state:'UNREAD'|'REVIEWED'; acknowledged:boolean; assignee_id:string|null; priority:'UNSET'|'LOW'|'MEDIUM'|'HIGH'|'URGENT'; version:number; updated_at:string|null; actor_id:string|null; owner:'PORTAL_ANNOTATION'; source_status_changed:false }
export interface Note {note_id:string;incident_id:string;note:string;actor_id:string;created_at:string}
export type Triage = Pick<Overlay,'version'|'review_state'|'acknowledged'|'assignee_id'|'priority'>
export declare class BusinessApiError extends Error { status:number; code:string; constructor(status:number,code:string) }
export declare function sourceKey(id:string,streamId?:string):string
export declare function newIntent():string
export declare function permissions(session:AuthSession|null,capabilities:Capabilities|null): {canTriage:boolean;canReadNotes:boolean;canAdmin:boolean;canAudit:boolean;networkActionsEnabled:false}
export declare function createBusinessClient(options?:{fetchImpl?:typeof fetch;onExpired?:()=>void}): {
  request(path:string,options?:{method?:string;body?:unknown;intent?:string;signal?:AbortSignal;csv?:boolean}):Promise<any>;
  adoptSession(data:AuthSession|null):AuthSession|void;
  me():Promise<AuthSession>; login(username:string,password:string):Promise<AuthSession>; logout():Promise<AuthSession>;
  capabilities():Promise<Capabilities>; overlay(kind:'incidents'|'alerts',id:string,streamId?:string):Promise<Overlay>;
  notes(id:string,streamId?:string,cursor?:string):Promise<{items:Note[];next_cursor:string|null}>; notesCsv(id:string,streamId?:string):Promise<string>;
  assignees():Promise<{items:{user_id:string;username:string}[]}>;
  triage(id:string,streamId:string|undefined,payload:Triage,intent:string):Promise<Overlay>;
  reviewAlert(id:string,streamId:string|undefined,payload:Pick<Triage,'version'|'review_state'|'acknowledged'>,intent:string):Promise<Overlay>;
  addNote(id:string,note:string,intent:string):Promise<Note>;
  users():Promise<{items:PortalUser[]}>; createUser(payload:{username:string;password:string;roles:Role[]},intent:string):Promise<PortalUser>;
  updateUser(id:string,payload:{version:number;roles:Role[];active:boolean},intent:string):Promise<PortalUser>;
  audit():Promise<{items:Audit[]}>;
}
export interface PortalUser {user_id:string;username:string;roles:Role[];active:boolean;version:number}
export interface Audit {audit_id:string;actor_id:string;action:string;target_ref:string|null;outcome:string;timestamp:string;request_id:string;source_ref:string|null;sequence:number;before:Record<string,unknown>|null;after:Record<string,unknown>|null}

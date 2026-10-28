import os, sqlite3, hashlib, hmac, secrets, json
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

DB_PATH = os.getenv("DATABASE_PATH", "resource_share.db")
app = FastAPI(title="ShareSpace — Trusted Resource Sharing", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory="static"), name="static")

def now():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', organization TEXT DEFAULT '',
      verified INTEGER NOT NULL DEFAULT 0, training TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS resources(
      id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id),
      title TEXT NOT NULL, category TEXT NOT NULL, description TEXT NOT NULL, location TEXT NOT NULL,
      available_from TEXT NOT NULL, available_to TEXT NOT NULL, rules TEXT NOT NULL,
      required_training TEXT NOT NULL DEFAULT '', membership_required INTEGER NOT NULL DEFAULT 0,
      supervision_required INTEGER NOT NULL DEFAULT 0, deposit REAL NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS bookings(
      id INTEGER PRIMARY KEY AUTOINCREMENT, resource_id INTEGER NOT NULL REFERENCES resources(id),
      user_id INTEGER NOT NULL REFERENCES users(id), start_at TEXT NOT NULL, end_at TEXT NOT NULL,
      purpose TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', decision_reason TEXT DEFAULT '',
      initial_condition TEXT DEFAULT '', final_condition TEXT DEFAULT '', checked_in_at TEXT DEFAULT '',
      checked_out_at TEXT DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS incidents(
      id INTEGER PRIMARY KEY AUTOINCREMENT, booking_id INTEGER NOT NULL REFERENCES bookings(id),
      reporter_id INTEGER NOT NULL REFERENCES users(id), incident_type TEXT NOT NULL,
      description TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER NOT NULL REFERENCES users(id),
      action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id INTEGER NOT NULL,
      details TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS waitlist(
      id INTEGER PRIMARY KEY AUTOINCREMENT, booking_id INTEGER NOT NULL UNIQUE REFERENCES bookings(id),
      position INTEGER NOT NULL, created_at TEXT NOT NULL
    );
    """)
    # Fictional demo accounts and resources
    count = c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
    if count == 0:
        users = [
          ("Admin Demo","admin@sharespace.test","Admin123!","admin","Demo Institution",1,"[\"Lab Safety\",\"3D Printer\"]"),
          ("Owner Demo","owner@sharespace.test","Owner123!","owner","Demo Institution",1,"[\"Lab Safety\"]"),
          ("Student Demo","student@sharespace.test","Student123!","user","Demo Institution",1,"[]"),
          ("New Member","member@sharespace.test","Member123!","user","Community Makerspace",0,"[]")
        ]
        for name,email,pw,role,org,verified,training in users:
            c.execute("INSERT INTO users(name,email,password_hash,role,organization,verified,training,created_at) VALUES(?,?,?,?,?,?,?,?)",
                      (name,email,hash_password(pw),role,org,verified,training,now()))
        owner_id = c.execute("SELECT id FROM users WHERE email='owner@sharespace.test'").fetchone()["id"]
        examples = [
          ("3D Printer — Prusa MK4","Fabrication","FDM 3D printer for prototypes and student projects.","Engineering Block, Lab 2","2026-01-01T09:00","2027-12-31T18:00","Attend printer induction. Clean the bed after use.","3D Printer",0,1,100),
          ("Electronics Workbench","Electronics","Bench with multimeter, soldering station and basic components.","Makerspace, Bench 4","2026-01-01T09:00","2027-12-31T18:00","Use ventilation; return tools to labelled drawers.","Lab Safety",1,1,0),
          ("Seminar Room — 12 seats","Space","Small room with display and whiteboard for team meetings.","Library, Room S-12","2026-01-01T08:00","2027-12-31T20:00","Leave room tidy; no food near equipment.","",0,0,0),
          ("DSLR Camera Kit","Media","Camera, lens, tripod and two batteries for approved projects.","Media Centre, Cabinet C","2026-01-01T10:00","2027-12-31T17:00","Handle with care; return all accessories.","",1,0,500)
        ]
        for x in examples:
            c.execute("""INSERT INTO resources(owner_id,title,category,description,location,available_from,available_to,rules,required_training,membership_required,supervision_required,deposit,status,created_at)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(owner_id,*x,"active",now()))
    c.commit(); c.close()

def hash_password(password):
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 180000)
    return salt + "$" + dk.hex()

def verify_password(password, stored):
    try:
        salt, expected = stored.split("$",1)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 180000).hex()
        return hmac.compare_digest(actual, expected)
    except Exception: return False

def token_for(user_id):
    # HMAC-signed stateless demo token. Set APP_SECRET in production.
    secret = os.getenv("APP_SECRET", "change-this-demo-secret-before-deployment")
    payload = str(user_id)
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + "." + sig

def current_user(request: Request):
    token = request.headers.get("X-Session-Token") or request.cookies.get("session")
    if not token or "." not in token: raise HTTPException(401, "Please sign in.")
    uid, sig = token.split(".",1)
    secret = os.getenv("APP_SECRET", "change-this-demo-secret-before-deployment")
    expected = hmac.new(secret.encode(), uid.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected): raise HTTPException(401, "Invalid session.")
    c=db(); u=c.execute("SELECT id,name,email,role,organization,verified,training FROM users WHERE id=?",(uid,)).fetchone(); c.close()
    if not u: raise HTTPException(401,"User not found.")
    return dict(u)

def log_action(actor_id, action, entity_type, entity_id, details=None):
    c=db(); c.execute("INSERT INTO audit_logs(actor_id,action,entity_type,entity_id,details,created_at) VALUES(?,?,?,?,?,?)",
      (actor_id,action,entity_type,entity_id,json.dumps(details or {}),now())); c.commit(); c.close()

def rowdict(row):
    if not row: return None
    d=dict(row)
    for k in ("training",): 
        if k in d:
            try:d[k]=json.loads(d[k])
            except:pass
    return d

class LoginIn(BaseModel):
    email: str
    password: str
class RegisterIn(BaseModel):
    name: str
    email: str
    password: str = Field(min_length=8)
    organization: str = ""
class ResourceIn(BaseModel):
    title: str
    category: str
    description: str
    location: str
    available_from: str
    available_to: str
    rules: str
    required_training: str = ""
    membership_required: bool = False
    supervision_required: bool = False
    deposit: float = Field(default=0, ge=0)
class BookingIn(BaseModel):
    resource_id: int
    start_at: str
    end_at: str
    purpose: str
class DecisionIn(BaseModel):
    decision: str
    reason: str = ""
class ConditionIn(BaseModel):
    condition: str = Field(min_length=3)
class IncidentIn(BaseModel):
    booking_id: int
    incident_type: str
    description: str

@app.on_event("startup")
def startup(): init_db()

@app.get("/", response_class=HTMLResponse)
def home():
    return FileResponse("static/index.html")

@app.get("/api/health")
def health(): return {"status":"ok","app":"ShareSpace"}

@app.post("/api/register")
def register(data: RegisterIn):
    c=db()
    try:
        cur=c.execute("INSERT INTO users(name,email,password_hash,role,organization,verified,training,created_at) VALUES(?,?,?,?,?,?,?,?)",
          (data.name,data.email.lower(),hash_password(data.password),"user",data.organization,0,"[]",now()))
        uid=cur.lastrowid; c.commit()
        user=c.execute("SELECT id,name,email,role,organization,verified,training FROM users WHERE id=?",(uid,)).fetchone()
        return {"token":token_for(uid),"user":rowdict(user)}
    except sqlite3.IntegrityError: raise HTTPException(409,"An account with this email already exists.")
    finally:c.close()

@app.post("/api/login")
def login(data: LoginIn):
    c=db(); u=c.execute("SELECT * FROM users WHERE email=?",(data.email.lower(),)).fetchone(); c.close()
    if not u or not verify_password(data.password,u["password_hash"]): raise HTTPException(401,"Email or password is incorrect.")
    return {"token":token_for(u["id"]),"user":{"id":u["id"],"name":u["name"],"email":u["email"],"role":u["role"],"organization":u["organization"],"verified":u["verified"],"training":json.loads(u["training"])}}

@app.get("/api/me")
def me(user=Depends(current_user)): return user

@app.get("/api/resources")
def list_resources(q: str="", category: str="", location: str="", c_user=Depends(current_user)):
    c=db(); sql="""SELECT r.*,u.name owner_name,u.organization owner_organization FROM resources r JOIN users u ON u.id=r.owner_id WHERE r.status='active'"""
    args=[]
    if q: sql+=" AND (r.title LIKE ? OR r.description LIKE ? OR r.category LIKE ?)"; args += [f"%{q}%"]*3
    if category: sql+=" AND r.category=?"; args.append(category)
    if location: sql+=" AND r.location LIKE ?"; args.append(f"%{location}%")
    sql+=" ORDER BY r.created_at DESC"
    rows=[dict(r) for r in c.execute(sql,args).fetchall()]; c.close()
    return rows

@app.post("/api/resources")
def create_resource(data: ResourceIn, user=Depends(current_user)):
    if user["role"] not in ("owner","admin"): raise HTTPException(403,"Only resource owners or admins can list resources.")
    if data.available_to <= data.available_from: raise HTTPException(400,"Availability end must be after start.")
    c=db(); cur=c.execute("""INSERT INTO resources(owner_id,title,category,description,location,available_from,available_to,rules,required_training,membership_required,supervision_required,deposit,status,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(user["id"],data.title,data.category,data.description,data.location,data.available_from,data.available_to,data.rules,data.required_training,int(data.membership_required),int(data.supervision_required),data.deposit,"active",now()))
    rid=cur.lastrowid;c.commit();c.close();log_action(user["id"],"resource_created","resource",rid,{"title":data.title})
    return {"id":rid,"message":"Resource listed successfully."}

@app.post("/api/bookings")
def create_booking(data: BookingIn, user=Depends(current_user)):
    if data.end_at <= data.start_at: raise HTTPException(400,"End time must be after start time.")
    c=db()
    resource=c.execute("SELECT * FROM resources WHERE id=? AND status='active'",(data.resource_id,)).fetchone()
    if not resource: c.close();raise HTTPException(404,"Resource not found.")
    if resource["owner_id"]==user["id"]: c.close();raise HTTPException(400,"You cannot book your own resource.")
    if data.start_at < resource["available_from"] or data.end_at > resource["available_to"]:
        c.close();raise HTTPException(400,"Requested time is outside the resource's availability.")
    if resource["membership_required"] and user["organization"] != resource["owner_id"] and not user["verified"]:
        c.close();raise HTTPException(403,"This resource requires verified membership. Ask the owner to verify your profile.")
    required=resource["required_training"].strip()
    training=user.get("training",[])
    if required and required not in training:
        c.close();raise HTTPException(403,f"Eligibility check failed: required training '{required}' is not on your profile.")
    # Limit active reservations to 2 per user in rolling 30 days to discourage monopolisation.
    recent=c.execute("SELECT COUNT(*) n FROM bookings WHERE user_id=? AND created_at>=? AND status IN ('pending','approved','checked_in')",
      (user["id"],(datetime.utcnow()-timedelta(days=30)).isoformat()+"Z")).fetchone()["n"]
    if recent>=2: c.close();raise HTTPException(429,"Fair-use limit: at most 2 active/pending bookings per user in 30 days.")
    conflict=c.execute("""SELECT COUNT(*) n FROM bookings WHERE resource_id=? AND status IN ('approved','checked_in')
      AND start_at < ? AND end_at > ?""",(data.resource_id,data.end_at,data.start_at)).fetchone()["n"]
    status="waiting" if conflict else "pending"
    cur=c.execute("""INSERT INTO bookings(resource_id,user_id,start_at,end_at,purpose,status,decision_reason,created_at,updated_at)
      VALUES(?,?,?,?,?,?,?,?,?)""",(data.resource_id,user["id"],data.start_at,data.end_at,data.purpose,status,
      "Time conflict: added to transparent waiting list." if conflict else "",now(),now()))
    bid=cur.lastrowid
    if status=="waiting":
        pos=c.execute("SELECT COALESCE(MAX(position),0)+1 p FROM waitlist WHERE booking_id IN (SELECT id FROM bookings WHERE resource_id=?)",(data.resource_id,)).fetchone()["p"]
        c.execute("INSERT INTO waitlist(booking_id,position,created_at) VALUES(?,?,?)",(bid,pos,now()))
    c.commit();c.close();log_action(user["id"],"booking_requested" if status=="pending" else "booking_waitlisted","booking",bid,{"resource_id":data.resource_id,"status":status})
    return {"id":bid,"status":status,"message":"Request submitted." if status=="pending" else "Resource is busy; request added to the waiting list."}

@app.get("/api/bookings")
def list_bookings(user=Depends(current_user)):
    c=db()
    rows=c.execute("""SELECT b.*,r.title resource_title,r.owner_id,r.location,u.name requester_name,u.email requester_email
      FROM bookings b JOIN resources r ON r.id=b.resource_id JOIN users u ON u.id=b.user_id
      WHERE b.user_id=? OR r.owner_id=? OR ?='admin' ORDER BY b.created_at DESC""",(user["id"],user["id"],user["role"])).fetchall()
    c.close();return [dict(r) for r in rows]

@app.post("/api/bookings/{booking_id}/decision")
def decide_booking(booking_id:int,data:DecisionIn,user=Depends(current_user)):
    if data.decision not in ("approved","rejected","waiting"):raise HTTPException(400,"Decision must be approved, rejected, or waiting.")
    c=db(); b=c.execute("SELECT b.*,r.owner_id,r.title FROM bookings b JOIN resources r ON r.id=b.resource_id WHERE b.id=?",(booking_id,)).fetchone()
    if not b:c.close();raise HTTPException(404,"Booking not found.")
    if user["role"]!="admin" and user["id"]!=b["owner_id"]:c.close();raise HTTPException(403,"Only the resource owner or an admin can decide.")
    if b["status"] not in ("pending","waiting"):c.close();raise HTTPException(400,"This booking can no longer be decided.")
    if data.decision=="approved":
        clash=c.execute("""SELECT COUNT(*) n FROM bookings WHERE resource_id=? AND id<>? AND status IN ('approved','checked_in')
          AND start_at < ? AND end_at > ?""",(b["resource_id"],booking_id,b["end_at"],b["start_at"])).fetchone()["n"]
        if clash:c.close();raise HTTPException(409,"Scheduling conflict: another booking is approved for this time.")
    c.execute("UPDATE bookings SET status=?,decision_reason=?,updated_at=? WHERE id=?",(data.decision,data.reason,now(),booking_id))
    c.execute("DELETE FROM waitlist WHERE booking_id=?",(booking_id,));c.commit();c.close()
    log_action(user["id"],"booking_"+data.decision,"booking",booking_id,{"reason":data.reason})
    return {"message":f"Booking {data.decision}.","status":data.decision}

@app.post("/api/bookings/{booking_id}/checkin")
def checkin(booking_id:int,data:ConditionIn,user=Depends(current_user)):
    c=db();b=c.execute("SELECT * FROM bookings WHERE id=?",(booking_id,)).fetchone()
    if not b:c.close();raise HTTPException(404,"Booking not found.")
    if b["user_id"]!=user["id"] and user["role"]!="admin":c.close();raise HTTPException(403,"Only the booking user can check in.")
    if b["status"]!="approved":c.close();raise HTTPException(400,"Only approved bookings can check in.")
    c.execute("UPDATE bookings SET status='checked_in',initial_condition=?,checked_in_at=?,updated_at=? WHERE id=?",(data.condition,now(),now(),booking_id))
    c.commit();c.close();log_action(user["id"],"checked_in","booking",booking_id,{"initial_condition":data.condition})
    return {"message":"Check-in recorded with initial condition."}

@app.post("/api/bookings/{booking_id}/checkout")
def checkout(booking_id:int,data:ConditionIn,user=Depends(current_user)):
    c=db();b=c.execute("SELECT * FROM bookings WHERE id=?",(booking_id,)).fetchone()
    if not b:c.close();raise HTTPException(404,"Booking not found.")
    if b["user_id"]!=user["id"] and user["role"]!="admin":c.close();raise HTTPException(403,"Only the booking user can check out.")
    if b["status"]!="checked_in":c.close();raise HTTPException(400,"This booking is not checked in.")
    c.execute("UPDATE bookings SET status='returned',final_condition=?,checked_out_at=?,updated_at=? WHERE id=?",(data.condition,now(),now(),booking_id))
    c.commit();c.close();log_action(user["id"],"checked_out","booking",booking_id,{"final_condition":data.condition})
    return {"message":"Return recorded."}

@app.post("/api/incidents")
def report_incident(data:IncidentIn,user=Depends(current_user)):
    c=db();b=c.execute("SELECT b.*,r.owner_id FROM bookings b JOIN resources r ON r.id=b.resource_id WHERE b.id=?",(data.booking_id,)).fetchone()
    if not b:c.close();raise HTTPException(404,"Booking not found.")
    if user["id"] not in (b["user_id"],b["owner_id"]) and user["role"]!="admin":c.close();raise HTTPException(403,"Only the booking parties can report an incident.")
    cur=c.execute("INSERT INTO incidents(booking_id,reporter_id,incident_type,description,status,created_at) VALUES(?,?,?,?,?,?)",
      (data.booking_id,user["id"],data.incident_type,data.description,"open",now()))
    iid=cur.lastrowid;c.commit();c.close();log_action(user["id"],"incident_reported","incident",iid,{"booking_id":data.booking_id,"type":data.incident_type})
    return {"id":iid,"message":"Incident reported for owner/manager review."}

@app.get("/api/incidents")
def incidents(user=Depends(current_user)):
    c=db();rows=c.execute("""SELECT i.*,b.user_id,r.owner_id,r.title resource_title,u.name reporter_name
      FROM incidents i JOIN bookings b ON b.id=i.booking_id JOIN resources r ON r.id=b.resource_id JOIN users u ON u.id=i.reporter_id
      WHERE b.user_id=? OR r.owner_id=? OR ?='admin' ORDER BY i.created_at DESC""",(user["id"],user["id"],user["role"])).fetchall();c.close();return [dict(r) for r in rows]

@app.post("/api/incidents/{incident_id}/resolve")
def resolve_incident(incident_id:int,user=Depends(current_user)):
    if user["role"] not in ("owner","admin"):raise HTTPException(403,"Only owners or admins can resolve incidents.")
    c=db();i=c.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone()
    if not i:c.close();raise HTTPException(404,"Incident not found.")
    b=c.execute("SELECT r.owner_id FROM bookings b JOIN resources r ON r.id=b.resource_id WHERE b.id=?",(i["booking_id"],)).fetchone()
    if user["role"]!="admin" and b["owner_id"]!=user["id"]:c.close();raise HTTPException(403,"Not your resource.")
    c.execute("UPDATE incidents SET status='resolved' WHERE id=?",(incident_id,));c.commit();c.close()
    log_action(user["id"],"incident_resolved","incident",incident_id,{})
    return {"message":"Incident marked resolved."}

@app.get("/api/audit")
def audit(user=Depends(current_user)):
    if user["role"] not in ("owner","admin"):raise HTTPException(403,"Audit history is available to owners and admins.")
    c=db()
    rows=c.execute("""SELECT a.*,u.name actor_name FROM audit_logs a JOIN users u ON u.id=a.actor_id
      WHERE ?='admin' OR a.entity_id IN (SELECT id FROM resources WHERE owner_id=?) OR
      (a.entity_type='booking' AND a.entity_id IN (SELECT b.id FROM bookings b JOIN resources r ON r.id=b.resource_id WHERE r.owner_id=?))
      ORDER BY a.id DESC LIMIT 200""",(user["role"],user["id"],user["id"])).fetchall()
    c.close();return [dict(r) for r in rows]

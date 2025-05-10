from pydantic import EmailStr
from typing import Dict, List, Optional
from fastapi import  BackgroundTasks, Body, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from db import admin_lobby,doctor_lobby, fix_mongo_id, keep_server_alive, patient_data,notification_data, send_email_task, update_questionnaire_completion
from models import Admin, Doctor, DoctorAssignRequest, EmailRequest, GoogleLoginRequest, LoginRequest, MarkReadRequest, Notification, PasswordResetRequest, Patient, PostSurgeryDetailsUpdateRequest, QuestionnaireAppendRequestLeft, QuestionnaireAppendRequestRight, QuestionnaireAssignedLeft, QuestionnaireAssignedRight, QuestionnaireResetRequest, QuestionnaireScoreAppendRequestLeft, QuestionnaireScoreAppendRequestRight, QuestionnaireUpdateRequest, SurgeryScheduleUpdateRequest
from datetime import date, datetime, timedelta
import asyncio
import resend
from jose import jwt, JWTError, ExpiredSignatureError
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"Message": "use '/docs' endpoint to find all the api related docs "}

@app.post("/registeradmin")
async def register_admin(admin: Admin):
    # Check if admin already exists
    existing_admin = await admin_lobby.find_one({"email": admin.email})
    if existing_admin:
        raise HTTPException(status_code=400, detail="Admin with this email already exists.")

    # Convert admin data to dict and insert into DB
    admin_data = admin.dict()
    result = await admin_lobby.insert_one(admin_data)

    return {
        "message": "Admin registered successfully.",
        "admin_id": str(result.inserted_id)
    }

@app.post("/registerdoctor")
async def register_doctor(doctor: Doctor):
    # Check if a doctor with same email, UHID, or phone number already exists
    existing = await doctor_lobby.find_one({
        "$or": [
            {"email": doctor.email},
            {"uhid": doctor.uhid},
        ]
    })
    if existing:
        raise HTTPException(status_code=400, detail="Doctor with this UHID or email or phone number already exists.")

    # Check if the admin who created this doctor exists
    admin = await admin_lobby.find_one({"email": doctor.admin_created})
    if not admin:
        raise HTTPException(status_code=404, detail="Admin who created this doctor was not found.")

    # Insert the doctor into the doctor_lobby collection
    doctor_data = doctor.dict()
    result = await doctor_lobby.insert_one(doctor_data)

    # Update admin's 'doctors_created' list with the new doctor's email or ID
    await admin_lobby.update_one(
        {"email": doctor.admin_created},
        {"$push": {"doctors_created": doctor.email}}  # or str(result.inserted_id) if preferred
    )

    return {
        "message": "Doctor registered successfully.",
        "doctor_id": str(result.inserted_id)
    }


@app.post("/registerpatient")
async def register_patient(patient: Patient):
    # Check if patient with same email or UHID already exists
    if await patient_data.find_one({"email": patient.email}) or await patient_data.find_one({"uhid": patient.uhid}):
        raise HTTPException(status_code=400, detail="Patient with this UHID or email or Phone Number already exists.")

    # Validate Admin exists
    admin = await admin_lobby.find_one({"email": patient.admin_assigned})
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found.")

    # Convert patient dict and ensure all dates are Mongo-friendly
    patient_dict = patient.dict()

    # Set the admin_name from the Admin record
    patient_dict["admin_name"] = admin["admin_name"]

    # Convert `date_of_surgery` if it exists
    if patient_dict.get("post_surgery_details") and patient_dict["post_surgery_details"].get("date_of_surgery"):
        dos = patient_dict["post_surgery_details"]["date_of_surgery"]
        patient_dict["post_surgery_details"]["date_of_surgery"] = datetime.combine(dos, datetime.min.time())

    # Convert timestamps in questionnaire_scores
    for key in ["questionnaire_scores_left", "questionnaire_scores_right"]:
        for score in patient_dict.get(key, []):
            if isinstance(score["timestamp"], date) and not isinstance(score["timestamp"], datetime):
                score["timestamp"] = datetime.combine(score["timestamp"], datetime.min.time())

    result = await patient_data.insert_one(patient_dict)

    # Update Admin's patients_created list
    await admin_lobby.update_one(
        {"email": patient.admin_assigned},
        {"$push": {"patients_created": patient.email}}
    )

    return {
        "message": "Patient registered successfully.",
        "patient_id": str(result.inserted_id)
    }


@app.post("/add-notification")
async def add_notification(notification: Notification):
    # Check if UHID exists in patient_data
    patient = await patient_data.find_one({"uhid": notification.uhid})
    if not patient:
        raise HTTPException(status_code=404, detail="Invalid UHID")

    # Convert Pydantic models to dicts
    new_notifications = [note.dict() for note in notification.notifications]

    # Check if a notification document for this UHID already exists
    existing = await notification_data.find_one({"uhid": notification.uhid})
    if existing:
        # Append new notifications to existing list
        await notification_data.update_one(
            {"uhid": notification.uhid},
            {"$push": {"notifications": {"$each": new_notifications}}}
        )
    else:
        # Create a new document
        await notification_data.insert_one({
            "uhid": notification.uhid,
            "notifications": new_notifications
        })

    return {"status": "success", "message": "Notification(s) added"}

@app.put("/mark-as-read")
async def mark_notification_as_read(
    data: MarkReadRequest = Body(...)
):
    # Check if UHID exists
    existing = await notification_data.find_one({"uhid": data.uhid})
    if not existing:
        raise HTTPException(status_code=404, detail="Invalid UHID")

    # Update the `read` status for the specific message
    result = await notification_data.update_one(
        {
            "uhid": data.uhid,
            "notifications.message": data.message
        },
        {
            "$set": {
                "notifications.$.read": 1
            }
        }
    )

    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Message not found or already read")

    return {"status": "success", "message": "Notification marked as read"}

@app.put("/update-doctor")
async def update_doctor_assignment(data: DoctorAssignRequest):
    # Validate patient exists
    patient = await patient_data.find_one({"uhid": data.uhid})
    if not patient:
        raise HTTPException(status_code=404, detail="Invalid UHID")

    # Validate doctor exists
    doctor = await doctor_lobby.find_one({"email": data.doctor_assigned})
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")

    # Perform update
    result = await patient_data.update_one(
        {"uhid": data.uhid},
        {
            "$set": {
                "doctor_assigned": data.doctor_assigned,
                "doctor_name": doctor["doctor_name"]
            }
        }
    )

    if result.modified_count:
        return {"message": "Doctor updated successfully"}
    else:
        return {"message": "No update performed. Doctor might already be assigned to this value."}

    
@app.put("/add-questionnaire-left")
async def add_questionnaire(data: QuestionnaireAppendRequestLeft):
    patient = await patient_data.find_one({"uhid": data.uhid})
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    # Get existing name-period pairs
    existing_pairs = set(
        (q["name"], q["period"])
        for q in patient.get("questionnaire_assigned_left", [])
    )

    # Filter out duplicates from the request
    new_questionnaires = [
        q.dict()
        for q in data.questionnaire_assigned_left
        if (q.name, q.period) not in existing_pairs
    ]

    if not new_questionnaires:
        return {"message": "No new questionnaire(s) to add"}

    # Optionally: pick latest period, or use the period of the first new questionnaire
    # If multiple questionnaires have different periods, you can choose how to handle
    new_status = new_questionnaires[0]["period"]  # For example, use the first one

    # Update the document
    result = await patient_data.update_one(
        {"uhid": data.uhid},
        {
            "$push": {"questionnaire_assigned_left": {"$each": new_questionnaires}},
            "$set": {"current_status": new_status}
        }
    )

    if result.modified_count:
        return {
            "message": "Questionnaire(s) added successfully to left and current_status updated",
            "updated_status": new_status
        }

    return {"message": "No changes made"}


@app.put("/add-questionnaire-scores-left")
async def add_questionnaire_scores(data: QuestionnaireScoreAppendRequestLeft):
    patient = await patient_data.find_one({"uhid": data.uhid})
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    result = await patient_data.update_one(
        {"uhid": data.uhid},
        {"$push": {"questionnaire_scores_left": {"$each": [score.dict() for score in data.questionnaire_scores_left]}}}
    )

    if result.modified_count:
        return {"message": "Score(s) added successfully to left"}
    return {"message": "No changes made"}

@app.put("/add-questionnaire-right")
async def add_questionnaire(data: QuestionnaireAppendRequestRight):
    patient = await patient_data.find_one({"uhid": data.uhid})
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    # Get existing name-period pairs
    existing_pairs = set(
        (q["name"], q["period"])
        for q in patient.get("questionnaire_assigned_right", [])
    )

    # Filter out duplicates from the request
    new_questionnaires = [
        q.dict()
        for q in data.questionnaire_assigned_right
        if (q.name, q.period) not in existing_pairs
    ]

    if not new_questionnaires:
        return {"message": "No new questionnaire(s) to add"}

    # Optionally: pick latest period, or use the period of the first new questionnaire
    # If multiple questionnaires have different periods, you can choose how to handle
    new_status = new_questionnaires[0]["period"]  # For example, use the first one

    # Update the document
    result = await patient_data.update_one(
        {"uhid": data.uhid},
        {
            "$push": {"questionnaire_assigned_right": {"$each": new_questionnaires}},
            "$set": {"current_status": new_status}
        }
    )

    if result.modified_count:
        return {
            "message": "Questionnaire(s) added successfully to right and current_status updated",
            "updated_status": new_status
        }

    return {"message": "No changes made"}


@app.put("/add-questionnaire-scores-right")
async def add_questionnaire_scores(data: QuestionnaireScoreAppendRequestRight):
    patient = await patient_data.find_one({"uhid": data.uhid})
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    result = await patient_data.update_one(
        {"uhid": data.uhid},
        {"$push": {"questionnaire_scores_right": {"$each": [score.dict() for score in data.questionnaire_scores_right]}}}
    )

    if result.modified_count:
        return {"message": "Score(s) added successfully to right"}
    return {"message": "No changes made"}

@app.put("/update-surgery-schedule")
async def update_surgery_schedule(data: SurgeryScheduleUpdateRequest):
    patient = await patient_data.find_one({"uhid": data.uhid})
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    result = await patient_data.update_one(
        {"uhid": data.uhid},
        {"$set": {"surgery_scheduled": data.surgery_scheduled.dict()}}
    )

    if result.modified_count:
        return {"message": "Surgery schedule updated successfully"}
    return {"message": "No changes made"}

@app.put("/update-post-surgery-details")
async def update_post_surgery_details(data: PostSurgeryDetailsUpdateRequest):
    patient = await patient_data.find_one({"uhid": data.uhid})
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    details_dict = data.post_surgery_details.dict()

    # Convert date to datetime if necessary
    if isinstance(details_dict.get("date_of_surgery"), date):
        details_dict["date_of_surgery"] = datetime.combine(
            details_dict["date_of_surgery"], datetime.min.time()
        )

    result = await patient_data.update_one(
        {"uhid": data.uhid},
        {"$set": {"post_surgery_details": details_dict}}
    )

    if result.modified_count:
        return {"message": "Post-surgery details updated successfully"}
    return {"message": "No changes made"}

@app.post("/google-login")
async def google_login(data: GoogleLoginRequest):
    email = data.email
    role = data.role

    if role == "doctor":
        doctor = await doctor_lobby.find_one({"email": email})
        if not doctor:
            raise HTTPException(status_code=404, detail="Doctor not found")
        return {"message": "Login successful", "role": "doctor", "user": fix_mongo_id(doctor)}

    elif role == "admin":
        admin = await admin_lobby.find_one({"email": email})
        if not admin:
            raise HTTPException(status_code=404, detail="Admin not found")
        return {"message": "Login successful", "role": "admin", "user": fix_mongo_id(admin)}

    elif role == "patient":
        patient = await patient_data.find_one({"email": email})
        if not patient:
            raise HTTPException(status_code=404, detail="Patient not found")
        return {"message": "Login successful", "role": "patient", "user": fix_mongo_id(patient)}

    raise HTTPException(status_code=400, detail="Invalid role")


@app.post("/login")
async def login_user(request: LoginRequest):
    # Choose the collection based on role
    collection = {
        "admin": admin_lobby,
        "doctor": doctor_lobby,
        "patient": patient_data
    }.get(request.role)

    if collection is None:
        raise HTTPException(status_code=400, detail="Invalid role")

    # Look for the user by email, uhid, or phone_number
    user = await collection.find_one({
        "$or": [
            {"email": request.identifier},
            {"uhid": request.identifier},
            {"phone_number": request.identifier}
        ]
    })

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user["password"] != request.password:
        raise HTTPException(status_code=401, detail="Invalid password")

    user["_id"] = str(user["_id"])  # convert ObjectId to str

    return {"message": "Login successful", "user": user}

@app.get("/patients/by-admin/{admin_email}", response_model=List[Patient])
async def get_patients_by_admin(admin_email: str):
    patients_cursor = patient_data.find({"admin_assigned": admin_email})
    patients = await patients_cursor.to_list(length=None)

    if not patients:
        raise HTTPException(status_code=404, detail="No patients found for this admin")

    return patients

@app.get("/getalldoctors", response_model=List[Doctor])
async def get_all_doctors():
    doctors_cursor = doctor_lobby.find()  # No filter, fetch all doctors
    doctors = await doctors_cursor.to_list(length=None)

    if not doctors:
        raise HTTPException(status_code=404, detail="No doctors found")

    return doctors

@app.get("/patients/by-doctor/{doctor_email}", response_model=List[Patient])
async def get_patients_by_doctor(doctor_email: str):
    patients_cursor = patient_data.find({"doctor_assigned": doctor_email})
    patients = await patients_cursor.to_list(length=None)

    if not patients:
        raise HTTPException(status_code=404, detail="No patients found for this doctor")

    return patients

@app.put("/update-questionnaire-status")
async def update_questionnaire_status(data: QuestionnaireUpdateRequest):
    result = await update_questionnaire_completion(
    uhid=data.uhid,
    name=data.name,
    period=data.period,
    completed=data.completed
)


    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Questionnaire not found or already completed.")
    
    return {"message": "Questionnaire status updated successfully."}

@app.put("/patients/reset-password")
async def reset_password(data: PasswordResetRequest):
    patient = await patient_data.find_one({"uhid": data.uhid})  # adjust for your DB
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    # Optionally, hash the password here
    await patient_data.update_one(
        {"uhid": data.uhid},
        {"$set": {"password": data.new_password}}
    )
    return {"message": "Password updated successfully"}

@app.put("/doctors/reset-password")
async def reset_doctor_password(data: PasswordResetRequest):
    doctor = await doctor_lobby.find_one({"uhid": data.uhid})  # Find doctor using uhid
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")

    # Optionally, hash the password before saving it (use a hash function if necessary)
    await doctor_lobby.update_one(
        {"uhid": data.uhid},
        {"$set": {"password": data.new_password}}  # Store the new password
    )
    return {"message": "Doctor's password updated successfully"}

@app.put("/admins/reset-password")
async def reset_admin_password(data: PasswordResetRequest):
    admin = await admin_lobby.find_one({"uhid": data.uhid})  # Find admin using uhid
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")

    # Optionally, hash the password before saving it (use a hash function if necessary)
    await admin_lobby.update_one(
        {"uhid": data.uhid},
        {"$set": {"password": data.new_password}}  # Store the new password
    )
    return {"message": "Admin's password updated successfully"}



@app.on_event("startup")
async def startup_event():
    asyncio.create_task(keep_server_alive())

@app.get("/")
def read_root():
    return {"status": "alive"}

active_connections = []

@app.websocket("/ws/message")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            print("Received:", data)

            # Broadcast to all connected clients
            for connection in active_connections:
                await connection.send_json(data)
    except WebSocketDisconnect:
        print("Client disconnected")
        active_connections.remove(websocket)


@app.post("/send/")
async def send_email(email_request: EmailRequest, background_tasks: BackgroundTasks):
    try:
        email = email_request.email
        subject = email_request.subject
        message = email_request.message

        # Add email sending task to background
        background_tasks.add_task(send_email_task, email, subject, message)
        
        return {"status": "success", "message": "Email sending initiated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get("/get-all-patients", response_model=List[Patient])
async def get_all_patients():
    patients_cursor = patient_data.find()
    patients = []
    async for patient in patients_cursor:
        patient["_id"] = str(patient["_id"])  # convert ObjectId to string
        patients.append(Patient(**patient))
    return patients

def ensure_datetime(value):
    if isinstance(value, date) and not isinstance(value, datetime):
        return datetime.combine(value, datetime.min.time())
    return value

@app.put("/patients/update-post-surgery")
async def update_post_surgery_details(
    uhid: str = Body(...),

    date_of_surgery: Optional[date] = Body(None),
    surgeon: Optional[str] = Body(None),
    surgery_name: Optional[str] = Body(None),
    procedure: Optional[str] = Body(None),
    implant: Optional[str] = Body(None),
    technology: Optional[str] = Body(None)
):
    # Build the update dict dynamically
    update_fields = {}
    
    if date_of_surgery is not None:
        # Ensure the date is converted to datetime
        update_fields["post_surgery_details.date_of_surgery"] = ensure_datetime(date_of_surgery)
    
    if surgeon is not None:
        update_fields["post_surgery_details.surgeon"] = surgeon
    if surgery_name is not None:
        update_fields["post_surgery_details.surgery_name"] = surgery_name
    if procedure is not None:
        update_fields["post_surgery_details.procedure"] = procedure
    if implant is not None:
        update_fields["post_surgery_details.implant"] = implant
    if technology is not None:
        update_fields["post_surgery_details.technology"] = technology

    if not update_fields:
        raise HTTPException(status_code=400, detail="No fields provided for update")

    result = await patient_data.update_one(
        {"uhid": uhid},
        {"$set": update_fields}
    )

    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Patient not found or no changes made")

    patient = await patient_data.find_one({"uhid": uhid})
    patient["_id"] = str(patient["_id"])
    return patient

@app.patch("/patients/{uhid}/vip/toggle")
async def toggle_vip_status(uhid: str):
    patient = await patient_data.find_one({"uhid": uhid})
    
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    
    current_vip = patient.get("vip", 0)
    new_vip = 0 if current_vip == 1 else 1
    
    await patient_data.update_one({"uhid": uhid}, {"$set": {"vip": new_vip}})
    
    return {
        "message": f"VIP status updated to {new_vip}",
        "uhid": uhid,
        "vip": new_vip
    }

@app.put("/patients/{uhid}/update-assigned-and-remove-score-left")
async def update_assigned_and_remove_score(uhid: str, data: QuestionnaireAssignedLeft):
    # Step 1: Update questionnaire_assigned_left (with array filter)
    update_result = await patient_data.update_one(
        {"uhid": uhid},
        {
            "$set": {
                "questionnaire_assigned_left.$[item].assigned_date": data.assigned_date,
                "questionnaire_assigned_left.$[item].deadline": data.deadline,
                "questionnaire_assigned_left.$[item].completed": data.completed
            },
            "$pull": {
                "questionnaire_scores_left": {
                    "name": data.name,
                    "period": data.period
                }
            }
        },
        array_filters=[{
            "item.name": data.name,
            "item.period": data.period
        }]
    )

    if update_result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Patient or matching questionnaire not found")

    return {"message": "Assigned questionnaire updated and corresponding score removed"}

@app.put("/patients/{uhid}/update-assigned-and-remove-score-right")
async def update_assigned_and_remove_score(uhid: str, data: QuestionnaireAssignedRight):
    # Step 1: Update questionnaire_assigned_left (with array filter)
    update_result = await patient_data.update_one(
        {"uhid": uhid},
        {
            "$set": {
                "questionnaire_assigned_right.$[item].assigned_date": data.assigned_date,
                "questionnaire_assigned_right.$[item].deadline": data.deadline,
                "questionnaire_assigned_right.$[item].completed": data.completed
            },
            "$pull": {
                "questionnaire_scores_right": {
                    "name": data.name,
                    "period": data.period
                }
            }
        },
        array_filters=[{
            "item.name": data.name,
            "item.period": data.period
        }]
    )

    if update_result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Patient or matching questionnaire not found")

    return {"message": "Assigned questionnaire updated and corresponding score removed"}

@app.put("/patients/{uhid}/reset-questionnaires-by-period-left")
async def reset_questionnaires_by_period(uhid: str, payload: QuestionnaireResetRequest):
    # Step 1: Remove questionnaire_assigned_left entries with matching period
    await patient_data.update_one(
        {"uhid": uhid},
        {"$pull": {"questionnaire_assigned_left": {"period": payload.period}}}
    )

    # Step 2: Remove questionnaire_scores_left with matching period + names
    for name in payload.questionnaires:
        await patient_data.update_one(
            {"uhid": uhid},
            {"$pull": {"questionnaire_scores_left": {"name": name, "period": payload.period}}}
        )

    # Step 3: Add new questionnaire_assigned_left entries
    now = datetime.utcnow()
    deadline = now + timedelta(days=3)

    new_entries = [{
        "name": name,
        "period": payload.period,
        "assigned_date": now.isoformat(),
        "deadline": deadline.isoformat(),
        "completed": 0
    } for name in payload.questionnaires]

    update_result = await patient_data.update_one(
        {"uhid": uhid},
        {"$push": {"questionnaire_assigned_left": {"$each": new_entries}}}
    )

    if update_result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Patient not found")

    return {
        "message": f"Reset questionnaires for period '{payload.period}'",
        "added": new_entries
    }

@app.put("/patients/{uhid}/reset-questionnaires-by-period-right")
async def reset_questionnaires_by_period(uhid: str, payload: QuestionnaireResetRequest):
    # Step 1: Remove questionnaire_assigned_left entries with matching period
    await patient_data.update_one(
        {"uhid": uhid},
        {"$pull": {"questionnaire_assigned_right": {"period": payload.period}}}
    )

    # Step 2: Remove questionnaire_scores_left with matching period + names
    for name in payload.questionnaires:
        await patient_data.update_one(
            {"uhid": uhid},
            {"$pull": {"questionnaire_scores_right": {"name": name, "period": payload.period}}}
        )

    # Step 3: Add new questionnaire_assigned_left entries
    new_entries = [{
        "name": name,
        "period": payload.period,
        "assigned_date": datetime.utcnow().isoformat(),
        "deadline": datetime.utcnow().isoformat(),
        "completed": 0
    } for name in payload.questionnaires]

    update_result = await patient_data.update_one(
        {"uhid": uhid},
        {"$push": {"questionnaire_assigned_right": {"$each": new_entries}}}
    )

    if update_result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Patient not found")

    return {
        "message": f"Reset questionnaires for period '{payload.period}'",
        "added": new_entries
    }

# Secret key for JWT (you can generate your own random key here)
SECRET_KEY = "your_secret_key"  # Replace with a secure random string
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1

def create_reset_token(uhid: str) -> str:
    """Generate JWT token for password reset."""
    expiration = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # Token expires in 15 minutes
    expire = datetime.utcnow() + expiration
    to_encode = {"sub": uhid, "exp": expire}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_reset_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uhid: str = payload.get("sub")
        if uhid is None:
            raise JWTError("User ID not found in token")
        return uhid
    except ExpiredSignatureError:
        # Token is expired
        return None
    except JWTError:
        # Token is invalid in other ways
        return None

# Function to send the reset link via email using SMTP
def send_reset_email(email: str, token: str):
    """Send password reset link via email using SMTP."""
    reset_url = f"http://localhost:3000?token={token}"

    sender_email = "adm.promxp@gmail.com"
    receiver_email = email
    password = "ucrwqqrajibptcjg"  # Consider storing this securely (env variable)

    smtp_server = "smtp.gmail.com"
    smtp_port = 465

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = "Password Reset Request"

    body = f"Click the link below to reset your password:\n{reset_url}"
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
            server.login(sender_email, password)
            text = msg.as_string()
            server.sendmail(sender_email, receiver_email, text)
        print("Password reset email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")


@app.post("/request_password_reset")
async def request_password_reset(
    background_tasks: BackgroundTasks,
    uhid: str,
    email: EmailStr = Query(..., description="Valid email address to send the reset link to"), 
):
    """Request password reset and send the reset link via email."""
    # Find user in the database
    user = await admin_lobby.find_one({"uhid": uhid}) or await doctor_lobby.find_one({"uhid": uhid}) or await patient_data.find_one({"uhid": uhid})
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Generate the reset token
    token = create_reset_token(uhid)
    
    # Send reset email
    background_tasks.add_task(send_reset_email, email, token)
    
    return {"message": "Password reset link sent to your email."}

def verify_reset_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None

@app.post("/reset_password")
async def reset_password(token: str, password_reset_request: PasswordResetRequest):
    # Decode token
    uhid = verify_reset_token(token)
    if uhid is None:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    
    # Check each collection to find the user
    user = await admin_lobby.find_one({"uhid": uhid})
    if user:
        result = await admin_lobby.update_one(
            {"uhid": uhid},
            {"$set": {"password": password_reset_request.new_password}}
        )
    else:
        user = await doctor_lobby.find_one({"uhid": uhid})
        if user:
            result = await doctor_lobby.update_one(
                {"uhid": uhid},
                {"$set": {"password": password_reset_request.new_password}}
            )
        else:
            user = await patient_data.find_one({"uhid": uhid})
            if user:
                result = await patient_data.update_one(
                    {"uhid": uhid},
                    {"$set": {"password": password_reset_request.new_password}}
                )
            else:
                raise HTTPException(status_code=404, detail="User not found")
    
    if result.modified_count == 0:
        raise HTTPException(status_code=400, detail="Failed to update the password")

    return {"message": "Password has been successfully reset."}
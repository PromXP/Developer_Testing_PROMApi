from datetime import date, datetime
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from typing_extensions import Literal

class GoogleLoginRequest(BaseModel):
    email: EmailStr
    role: Literal["patient", "doctor", "admin"]

class LoginRequest(BaseModel):
    identifier: str  # email OR uhid OR phone number
    password: str
    role: str  # "admin", "doctor", "patient"

class Doctor(BaseModel):
    doctor_name: str
    gender: Literal["male", "female", "other"]
    age: int
    email: EmailStr
    designation: str
    uhid : str
    phone_number : str
    blood_group: str
    password: str
    admin_created: str
    patients_assigned: List[str] = []

    class Config:
        schema_extra = {
            "example": {
                "doctor_name": "Dr. John Smith",
                "gender": "male",
                "age": 45,
                "uhid" : "UH123456",
                "admin_created": "APM",
                "designation": "leg surgeon",
                "phone_number": "1234567890",
                "blood_group": "A+",
                "email": "dr.john@example.com",
                "password": "securePass123",
                "patients_assigned": ["patient_id_1", "patient_id_2"]
            }
        }

class Admin(BaseModel):
    admin_name: str
    gender: Literal["male", "female", "other"]
    age: int
    password: str
    uhid : str
    phone_number : str
    email: EmailStr
    doctors_created: List[str] = []
    patients_created: List[str] = []

    class Config:
        schema_extra = {
            "example": {
                "admin_name": "Alice Admin",
                "gender": "female",
                "age": 35,
                "phone_number": "1234567890",
                "password": "adminSecure@456",
                "email": "alice.admin@example.com",
                "doctors_created": ["doctor1", "doctor2"],
                "patients_created": ["patient_id_1", "patient_id_2"]
            }
        }

class QuestionnaireUpdateRequest(BaseModel):
    uhid: str
    name: str
    period: str
    completed: int = 1  # Default is 1 (completed)

class QuestionnaireAssigned(BaseModel):
    name: str
    period: str
    assigned_date: str
    deadline: str
    completed: Literal[0, 1]

class QuestionnaireScore(BaseModel):
    name: str
    score: List[float]
    period: str
    timestamp: datetime

class SurgeryScheduled(BaseModel):
    date: str
    time: str  # or use datetime if you prefer combining date & time

class PostSurgeryDetails(BaseModel):
    date_of_surgery: date
    surgeon: str
    surgery_name: str
    procedure: str
    implant: str
    technology: str

class Patient(BaseModel):
    uhid: str
    first_name: str
    last_name: str
    password: str
    dob: str
    age: int
    blood_grp: str
    gender: Literal["male", "female", "other"]
    height: int
    weight: int
    bmi: float
    email: EmailStr
    phone_number: str
    doctor_assigned: Optional[str] = None
    admin_assigned: Optional[str] = None
    doctor_name: Optional[str] = None
    admin_name: Optional[str] = None
    questionnaire_assigned: Optional[List[QuestionnaireAssigned]] = []
    questionnaire_scores: Optional[List[QuestionnaireScore]] = []
    surgery_scheduled: Optional[SurgeryScheduled] = None
    post_surgery_details: Optional[PostSurgeryDetails] = None
    current_status: str

    class Config:
        schema_extra = {
            "example": {
                "uhid": "UH123456",
                "first_name": "John",
                "last_name": "Doe",
                "password": "password123",
                "dob": "1990-05-15",
                "age": 34,
                "blood_grp": "O+",
                "gender": "male",
                "height": 175.0,
                "weight": 70.0,
                "bmi": 22.86,
                "email": "john.doe@example.com",
                "phone_number": "1234567890",
                "doctor_assigned": "doctor_01",
                "admin_assigned": "admin_01",
                "doctor_name": "doctor_01",
                "admin_name": "admin_01",
                "questionnaire_assigned": [
                    {
                        "name": "Mobility Survey",
                        "period": "weekly",
                        "assigned_date": "2025-04-01T10:00:00",
                        "deadline": "2025-04-01T10:00:00",
                        "completed": 0
                    },
                    {
                        "name": "Pain Assessment",
                        "period": "daily",
                        "assigned_date": "2025-04-02T08:00:00",
                        "deadline": "2025-04-01T10:00:00",
                        "completed": 1
                    }
                ],
                "questionnaire_scores": [
                    {
                        "name": "Mobility Survey",
                        "score": 85.5,
                        "period": "weekly",
                        "timestamp": "2025-04-01T10:30:00"
                    },
                    {
                        "name": "Pain Assessment",
                        "score": 92.0,
                        "period": "weekly",
                        "timestamp": "2025-04-02T08:30:00"
                    }
                ],
                "surgery_scheduled": {
                    "date": "2025-05-10",
                    "time": "08:00"
                },
                "post_surgery_details": {
                    "date_of_surgery": "2025-05-10",
                    "surgeon": "Dr. Strange",
                    "surgery_name": "knee replacement",
                    "procedure": "Knee Replacement is a part of leg helping",
                    "implant": "Titanium",
                    "technology": "Robotic Assisted"
                },
                "current_status": "pre_op",
            }
        }

class ReminderAlertMessage(BaseModel):
    message: str
    timestamp: datetime
    read: Literal[0, 1]

class Notification(BaseModel):
    uhid: str
    notifications: List[ReminderAlertMessage] = []

    class Config:
        schema_extra = {
            "example": {
                "uhid": "UH123456",
                "notifications": [
                    {
                        "message": "Please complete your questionnaire.",
                        "timestamp": "2025-04-05T12:00:00",
                        "read": 0
                    },
                    {
                        "message": "Your surgery is scheduled for May 10 at 08:00.",
                        "timestamp": "2025-04-07T09:00:00",
                        "read": 1
                    }
                ]
            }
        }

class MarkReadRequest(BaseModel):
    uhid: str
    message: str  

class DoctorAssignRequest(BaseModel):
    uhid: str
    doctor_assigned: str


class QuestionnaireAppendRequest(BaseModel):
    uhid: str
    questionnaire_assigned: List[QuestionnaireAssigned]

class QuestionnaireScoreAppendRequest(BaseModel):
    uhid: str
    questionnaire_scores: List[QuestionnaireScore]

class SurgeryScheduleUpdateRequest(BaseModel):
    uhid: str
    surgery_scheduled: SurgeryScheduled

class PostSurgeryDetailsUpdateRequest(BaseModel):
    uhid: str
    post_surgery_details: PostSurgeryDetails

class PasswordResetRequest(BaseModel):
    uhid: str
    new_password: str

class EmailRequest(BaseModel):
    email: str
    subject: str
    message: str
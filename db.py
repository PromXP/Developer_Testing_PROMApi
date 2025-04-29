from motor import motor_asyncio
import logging
import asyncio
import resend

# MongoDB setup  
client = motor_asyncio.AsyncIOMotorClient("mongodb+srv://admpromxp:admpromxp@cluster0.tqkmast.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
database = client.Main
admin_lobby = database.Admin_Lobby 
doctor_lobby = database.Doctor_Lobby 
patient_data = database.Patient_Data
notification_data = database.Notification_Data


# Load the API key from environment variables
resend.api_key = "re_YwfA61tz_Ho8naTfud7ZaUqZrF7efdo1d"

def fix_mongo_id(document):
    if document is None:
        return document
    document["_id"] = str(document["_id"])
    return document


async def keep_server_alive():
    while True:
        logging.info("🔁 Tick: Server is alive.")
        await asyncio.sleep(105)  # 1 minute 45 seconds = 105 seconds

def update_questionnaire_completion(uhid: str, name: str, period: str, completed: int = 1):
    filter_query = {
        "uhid": uhid,
        "questionnaire_assigned": {
            "$elemMatch": {
                "name": name,
                "period": period
            }
        }
    }

    update_query = {
        "$set": {
            "questionnaire_assigned.$.completed": completed
        }
    }

    result = patient_data.update_one(filter_query, update_query)
    return result

def send_email_task(email: str, subject: str, message: str):
    try:
        resend.Emails.send({
            "from": "Xolabs Health <ronaldshawv@thewad.co>",
            "to": [email],
            "subject": subject,
            "html": """
            <div style="font-family: Arial, sans-serif; background-color: #f5f5f5; padding: 40px;">
              <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.05);">
                <tr>
                  <td style="background-color: #4f46e5; padding: 20px; text-align: center; color: white;">
                    <h1 style="margin: 0; font-size: 24px;">🏥 Welcome to Parvathy Hospital</h1>
                  </td>
                </tr>
                <tr>
                  <td style="padding: 30px;">
                    <p style="font-size: 16px; color: #333;">Dear Patient,</p>
                    <p style="font-size: 16px; color: #333;">{message}</p>
                    <p style="margin-top: 30px; text-align: center;">
                      <a href="https://promwebformslower.onrender.com" style="display: inline-block; background-color: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-size: 16px;">
                        Click here to Open The Questionnaire
                      </a>
                    </p>
                  </td>
                </tr>
                <tr>
                  <td style="background-color: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #777;">
                    ©2024 <a href="https://thexolabs.in" style="color: #777; text-decoration: none;">XoLabs.in</a>. All rights reserved.
                  </td>
                </tr>
              </table>
            </div>
            """
        })
    except Exception as e:
        print(f"Error sending email: {e}")

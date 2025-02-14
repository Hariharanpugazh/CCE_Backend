import jwt
import json
from datetime import datetime, timedelta, timezone
from django.http import JsonResponse
from bson import ObjectId
from pymongo import MongoClient
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.hashers import make_password, check_password
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
from rest_framework import status
import base64
from bson.errors import InvalidId
import re  # Add this import for regex
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Create your views here.
JWT_SECRET = "secret"
JWT_ALGORITHM = "HS256"


def generate_tokens(admin_user):
    """
    Generate tokens for authentication. Modify this with JWT implementation if needed.
    """
    access_payload = {
        'admin_user': str(admin_user),
        'role':'admin',
        "exp": datetime.utcnow() + timedelta(days=1),
        "iat": datetime.utcnow(),
    }

    # Encode the token
    token = jwt.encode(access_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {'jwt': token}

def generate_tokens_superadmin(superadmin_user):
    """
    Generate tokens for authentication. Modify this with JWT implementation if needed.
    """
    access_payload = {
        'superadmin_user': str(superadmin_user),
        'role':'superadmin',
        "exp": datetime.utcnow() + timedelta(days=1),
        "iat": datetime.utcnow(),
    }

    # Encode the token
    token = jwt.encode(access_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"jwt": token}


# MongoDB connection
client = MongoClient('mongodb+srv://ihub:ihub@cce.ksniz.mongodb.net/')
db = client['CCE']
admin_collection = db['admin']
internship_collection = db['internships']
job_collection = db['jobs']
achievement_collection = db['achievement']
superadmin_collection = db['superadmin']
student_collection = db['students']
reviews_collection = db['reviews']
study_material_collection = db['studyMaterial']
contactus_collection = db["contact_us"]
student_achievement_collection=db["student_achievement"]

# Dictionary to track failed login attempts
failed_login_attempts = {}
lockout_duration = timedelta(minutes=2)  # Time to lock out after 3 failed attempts

# Function to check if the password is strong
def is_strong_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must include at least one digit."
    if not re.search(r"[@$!%*?&#]", password):
        return False, "Password must include at least one special character."
    return True, ""

# Function to send confirmation email
def send_confirmation_email(to_email, name, password):
    subject = "Admin Account Created"
    body = f"""
    Your admin account has been successfully created on the CCE platform.
    Username: {name}
    Password: {password}
    Please keep your credentials safe and secure.
    """

    msg = MIMEMultipart()
    msg['From'] = settings.EMAIL_HOST_USER
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to the Gmail SMTP server
        server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
        server.starttls()  # Secure the connection
        server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)  # Login with credentials
        text = msg.as_string()
        server.sendmail(settings.EMAIL_HOST_USER, to_email, text)  # Send the email
        server.quit()  # Close the connection
        print(f"Confirmation email sent to {to_email}")
    except Exception as e:
        print(f"Error sending email: {str(e)}")

@csrf_exempt
def admin_signup(request):
    if request.method == "POST":
        try:
            # Parse the request payload
            data = json.loads(request.body)
            name = data.get('name')
            email = data.get('email')
            password = data.get('password')
            department = data.get('department')  # New field
            college_name = data.get('college_name')  # New field

            # Validate required fields
            if not all([name, email, password, department, college_name]):
                return JsonResponse({'error': 'All fields are required'}, status=400)

            # Check if the email already exists
            if admin_collection.find_one({'email': email}):
                return JsonResponse({'error': 'This email is already assigned to an admin'}, status=400)

            # Check if the password is strong
            is_valid, error_message = is_strong_password(password)
            if not is_valid:
                return JsonResponse({'error': error_message}, status=400)

            # Hash the password
            hashed_password = make_password(password)

            # Create the admin user document
            admin_user = {
                'name': name,
                'email': email,
                'password': hashed_password,
                'department': department,  # Store department
                'college_name': college_name,  # Store college name
                'status': 'active',  # Default status is active
                'created_at': datetime.now(),  # Store account creation date
                'last_login': None  # Initially, no last login
            }

            # Insert the document into the collection
            admin_collection.insert_one(admin_user)

            # Send confirmation email with username and password
            send_confirmation_email(email, name, password)

            return JsonResponse({'message': 'Admin user created successfully, confirmation email sent.'}, status=201)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)


def generate_reset_token(length=6):
    return ''.join(random.choices(string.digits, k=length))
 
@csrf_exempt
def admin_login(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get("email")
            password = data.get("password")

            # Check if the email contains "sns"
            if "@sns" not in email:
                return JsonResponse({'error': 'Email must contain domain id'}, status=400)

            # Check lockout status
            if email in failed_login_attempts:
                lockout_data = failed_login_attempts[email]
                if lockout_data['count'] >= 3 and datetime.now() < lockout_data['lockout_until']:
                    return JsonResponse({'error': 'Too many failed attempts. Please try again after 2 minutes.'}, status=403)

            # Find the admin user by email
            admin_user = admin_collection.find_one({'email': email})

            if admin_user is None:
                return JsonResponse({'error': 'Account not found with this email id'}, status=404)

            # Check if the account is active
            if not admin_user.get('status', 'active') == 'active':
                return JsonResponse({'error': 'Admin account is deactivated. Please contact support.'}, status=403)

            if check_password(password, admin_user['password']):
                # Clear failed attempts after successful login
                failed_login_attempts.pop(email, None)

                # Generate JWT token
                admin_id = admin_user.get('_id')
                tokens = generate_tokens(admin_id)

                # Update last login timestamp
                admin_collection.update_one({'email': email}, {'$set': {'last_login': datetime.now()}})

                # Set the username in cookies
                response = JsonResponse({'username': admin_user['name'], 'tokens': tokens, 'last_login': datetime.now()}, status=200)

                return response
            else:
                # Track failed attempts
                if email not in failed_login_attempts:
                    failed_login_attempts[email] = {'count': 1, 'lockout_until': None}
                else:
                    failed_login_attempts[email]['count'] += 1
                    if failed_login_attempts[email]['count'] >= 3:
                        failed_login_attempts[email]['lockout_until'] = datetime.now() + lockout_duration

                return JsonResponse({'error': 'Invalid email or password.'}, status=401)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

# def generate_reset_token(length=4):
#     # return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
#     return ''.join(random.choices(string.digits, k=length))

@api_view(["POST"])
@permission_classes([AllowAny])
def forgot_password(request):
    try:
        email = request.data.get('email')
        user = admin_collection.find_one({"email": email})
        if not user:
            return Response({"error": "Email not found"}, status=400)
        
        reset_token = generate_reset_token()
        expiration_time = datetime.utcnow() + timedelta(hours=1)
        
        admin_collection.update_one(
            {"email": email},
            {"$set": {"password_reset_token": reset_token, "password_reset_expires": expiration_time}}
        )
        
        send_mail(
            'Password Reset Request',
            f'Use this token to reset your password: {reset_token}',
            settings.DEFAULT_FROM_EMAIL,
            [email],
        )
        
        return Response({"message": "Password reset token sent to your email"}, status=200)
    except Exception as e:
        return Response({"error": str(e)}, status=500)
    
@api_view(["POST"])
@permission_classes([AllowAny])
def verify_otp(request):
    try:
        email = request.data.get('email')
        otp = request.data.get('otp')
        
        user = admin_collection.find_one({"email": email})
        if not user:
            return Response({"error": "User not found"}, status=404)
        
        if user.get("password_reset_token") != otp:
            return Response({"error": "Invalid OTP"}, status=400)
        
        if user.get("password_reset_expires") < datetime.utcnow():
            return Response({"error": "OTP has expired"}, status=400)
        
        return Response({"message": "verification successfully"}, status=200)
    except Exception as e:
        return Response({"error": str(e)}, status=500)
    
from django.contrib.auth.hashers import make_password

@csrf_exempt
def reset_password(request):
    """Reset Password Function"""
    if request.method == 'POST':
        try:
            # Parse the request payload
            data = json.loads(request.body)
            email = data.get('email')
            new_password = data.get('newPassword')

            # Validate the request data
            if not email or not new_password:
                return JsonResponse({"error": "Email and new password are required."}, status=400)

            # Fetch the user by email
            user = admin_collection.find_one({"email": email})
            if not user:
                return JsonResponse({"error": "User not found."}, status=404)

            # Hash the new password
            hashed_password = make_password(new_password)

            # Ensure hashed password starts with "pbkdf2_sha256$"
            if not hashed_password.startswith("pbkdf2_sha256$"):
                return JsonResponse({"error": "Failed to hash the password correctly."}, status=500)

            # Update the password in MongoDB
            result = admin_collection.update_one(
                {"email": email},
                {"$set": {
                    "password": hashed_password,
                    "password_reset_token": None,  # Clear reset token
                    "password_reset_expires": None  # Clear expiration time
                }}
            )

            if result.modified_count == 0:
                return JsonResponse({"error": "Failed to update the password in MongoDB."}, status=500)

            return JsonResponse({"message": "Password reset successfully"}, status=200)

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)

    return JsonResponse({"error": "Invalid request method. Use POST."}, status=405)

@csrf_exempt
def get_admin_list(request):
    try:
        # Fetch all documents from the admin_collection
        admins = admin_collection.find()
        admin_list = []

        for admin in admins:
            admin["_id"] = str(admin["_id"])  # Convert ObjectId to string
            admin_list.append(admin)

        return JsonResponse({"admins": admin_list}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def admin_details(request, id):
    if request.method == 'GET':
        try:
            admin = admin_collection.find_one({'_id': ObjectId(id)})
            if not admin:
                return JsonResponse({'error': 'Admin not found'}, status=404)

            admin['_id'] = str(admin['_id'])

            last_login = admin.get('last_login')
            if last_login:
                last_login = last_login.strftime('%Y-%m-%d %H:%M:%S')
            else:
                last_login = "Never logged in"

            admin_data = {
                '_id': admin['_id'],
                'name': admin.get('name', 'N/A'),
                'email': admin.get('email', 'N/A'),
                'status': admin.get('status', 'active'),
                'department': admin.get('department', 'N/A'),
                'college_name': admin.get('college_name', 'N/A'),
                'created_at': datetime.now(),
                'last_login': last_login
            }

            jobs = job_collection.find({'admin_id': str(admin['_id'])})
            jobs_list = []
            for job in jobs:
                job['_id'] = str(job['_id'])
                job_data = job.get('job_data', {})
                job_data['_id'] = job['_id']
                job_data['updated_at'] = job.get('updated_at')  # Include updated_at field
                jobs_list.append(job_data)

            return JsonResponse({'admin': admin_data, 'jobs': jobs_list}, status=200)

        except Exception as e:
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
@csrf_exempt
def edit_admin_details(request, id):
    if request.method == 'PUT':
        try:
            data = json.loads(request.body)
            admin = admin_collection.find_one({'_id': ObjectId(id)})
            if not admin:
                return JsonResponse({'error': 'Admin not found'}, status=404)

            # Update fields if provided in the request
            if 'name' in data:
                admin['name'] = data['name']
            if 'email' in data:
                admin['email'] = data['email']
            if 'status' in data:
                admin['status'] = data['status']
            if 'department' in data:
                admin['department'] = data['department']
            if 'college_name' in data:
                admin['college_name'] = data['college_name']

            # Save the updated admin details back to the database
            admin_collection.update_one({'_id': ObjectId(id)}, {'$set': admin})

            return JsonResponse({'success': 'Admin details updated successfully'}, status=200)

        except Exception as e:
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def admin_status_update(request, id):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            new_status = data.get("status")

            if new_status not in ["active", "Inactive"]:
                return JsonResponse({'error': 'Invalid status value'}, status=400)

            update_result = admin_collection.update_one({'_id': ObjectId(id)}, {'$set': {'status': new_status}})

            if update_result.matched_count == 0:
                return JsonResponse({'error': 'Admin not found'}, status=404)

            return JsonResponse({'message': f'Admin status updated to {new_status}'}, status=200)

        except Exception as e:
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    
@csrf_exempt
def super_admin_signup(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            name = data.get("name")
            email = data.get("email")
            password = data.get("password")

            # Check if the email contains "sns"
            if "@sns" not in email:
                return JsonResponse(
                    {"error": "Email must contain domain id"}, status=400
                )

            # Check if the email already exists
            if superadmin_collection.find_one({'email': email}):
                return JsonResponse({'error': 'Super admin user with this email already exists'}, status=400)

            # Check if the password is strong
            if not re.match(
                r"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", password
            ):
                return JsonResponse(
                    {
                        "error": "Password must be at least 8 characters long, contain an uppercase letter, a number, and a special character"
                    },
                    status=400,
                )

            # Hash the password
            password = make_password(password)

            # Create the super admin user document
            super_admin_user = {
                'name': name,
                'email': email,
                'password': password,
            }

            # Insert the document into the collection
            superadmin_collection.insert_one(super_admin_user)

            return JsonResponse({'message': 'Super admin user created successfully'}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def super_admin_login(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get("email")
            password = data.get("password")

            # Check if the email contains "sns"
            if "@sns" not in email:
                return JsonResponse({'error': 'Email must contain domain id'}, status=400)

            # Check lockout status
            if email in failed_login_attempts:
                lockout_data = failed_login_attempts[email]
                if lockout_data['count'] >= 3 and datetime.now() < lockout_data['lockout_until']:
                    return JsonResponse({'error': 'Too many failed attempts. Please try again after 2 minutes.'}, status=403)

            # Find the super admin user by email
            super_admin_user = superadmin_collection.find_one({'email': email})

            if super_admin_user is None:
                return JsonResponse({'error': 'Account not found with this email id'}, status=404)

            if check_password(password, super_admin_user['password']):
                # Clear failed attempts after successful login
                failed_login_attempts.pop(email, None)

                # Generate JWT token
                super_admin_id = super_admin_user.get('_id')
                tokens = generate_tokens_superadmin(super_admin_id)
                return JsonResponse({'username': super_admin_user['name'], 'tokens': tokens}, status=200)
            else:
                # Track failed attempts
                if email not in failed_login_attempts:
                    failed_login_attempts[email] = {'count': 1, 'lockout_until': None}
                else:
                    failed_login_attempts[email]['count'] += 1
                    if failed_login_attempts[email]['count'] >= 3:
                        failed_login_attempts[email]['lockout_until'] = datetime.now() + lockout_duration

                return JsonResponse({'error': 'Invalid email or password.'}, status=401)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

    
# ============================================================== JOBS ======================================================================================
    
@csrf_exempt
@api_view(["POST"])
def job_post(request):
    try:
        data = json.loads(request.body)
    
        role = data.get('role')
        print(role)
        auto_approval_setting = superadmin_collection.find_one({"key": "auto_approval"})
        is_auto_approval = auto_approval_setting.get("value", False) if auto_approval_setting else False

        is_publish = None  # Default: Pending (null)
        userid = data.get('userId')

        if not userid:
            return Response({"error": "Userid not found"}, status=status.HTTP_401_UNAUTHORIZED)

        if role == 'admin':            
            if is_auto_approval:
                is_publish = True  # Auto-approve enabled, mark as approved

        elif role == 'superadmin':
 
            is_publish = True  # Superadmin posts are always approved

        data = json.loads(request.body)

        application_deadline_str = data.get('application_deadline')
        application_deadline = datetime.fromisoformat(application_deadline_str.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)

        current_status = "active" if application_deadline >= now else "expired"

        # Prepare job data
        job_post = {
            "job_data": {
                "title": data.get('title'),
                "company_name": data.get('company_name'),
                "company_overview": data.get('company_overview'),
                "company_website": data.get('company_website'),
                "job_description": data.get('job_description'),
                "key_responsibilities": data.get('key_responsibilities'),
                "required_skills": data.get('required_skills'),
                "education_requirements": data.get('education_requirements'),
                "experience_level": data.get('experience_level'),
                "salary_range": data.get('salary_range'),
                "benefits": data.get('benefits'),
                "job_location": data.get('job_location'),
                "work_type": data.get('work_type'),
                "work_schedule": data.get('work_schedule'),
                "application_instructions": data.get('application_instructions'),
                "application_deadline": data.get('application_deadline'),
                "contact_email": data.get('contact_email'),
                "contact_phone": data.get('contact_phone'),
                "job_link": data.get('job_link'),
                "selectedCategory": data.get('selectedCategory'),
                "selectedWorkType": data.get('selectedWorkType')
            },
            "admin_id" if role == "admin" else "superadmin_id":  userid,#admin_id if role == "admin" else superadmin_id,  # Save the admin_id from the token
            "is_publish": is_publish,  # Auto-approve if enabled
            "status": current_status,
            "updated_at": datetime.now()
        }

        # Insert the job post into the database
        job_collection.insert_one(job_post)

        return Response(
            {
                "message": "Job stored successfully",
                "auto_approved": is_auto_approval
            },
            status=status.HTTP_201_CREATED
        )
    except Exception as e:
        print(e)
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
        
@csrf_exempt
def get_jobs_for_mail(request):
    try:
        jobs = job_collection.find()
        job_list = []

        for job in jobs:
            job["_id"] = str(job["_id"])  # Convert ObjectId to string

            # Convert is_publish to readable status
            approval_status = "Waiting for Approval" if job.get("is_publish") is None else (
                "Approved" if job["is_publish"] else "Rejected"
            )

            # Fetch admin details using admin_id
            admin_id = job.get("admin_id")
            admin_name = "Unknown Admin"
            if admin_id:
                admin = admin_collection.find_one({"_id": ObjectId(admin_id)})
                if admin:
                    admin_name = admin.get("name", "Unknown Admin")

            # Ensure job_data exists and has application_deadline
            if "job_data" in job and "application_deadline" in job["job_data"]:
                deadline = job["job_data"]["application_deadline"]
                if deadline:
                    if isinstance(deadline, datetime):
                        # If deadline is already a datetime object, format it directly
                        formatted_deadline = deadline.strftime("%Y-%m-%d")
                    elif isinstance(deadline, str):
                        try:
                            # Try parsing full datetime format
                            formatted_deadline = datetime.strptime(deadline, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d")
                        except ValueError:
                            try:
                                # If the first format fails, try the plain date format
                                formatted_deadline = datetime.strptime(deadline, "%Y-%m-%d").strftime("%Y-%m-%d")
                            except ValueError:
                                # If neither format works, keep it as is (to avoid crashes)
                                formatted_deadline = deadline
                    else:
                        formatted_deadline = str(deadline)  # Fallback to string conversion

                    job["job_data"]["application_deadline"] = formatted_deadline  # Update formatted value

            # Add human-readable approval status and admin name
            job["approval_status"] = approval_status
            job["admin_name"] = admin_name  # Attach admin name

            job_list.append(job)

        return JsonResponse({"jobs": job_list}, status=200, safe=False)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
 
@csrf_exempt
@api_view(["POST"])
def toggle_auto_approval(request):
    """
    API to enable or disable auto-approval.
    """
    try:
        data = json.loads(request.body)
        is_auto_approval = data.get("is_auto_approval", False)  # Default is False

        # Save or update the setting in MongoDB
        superadmin_collection.update_one(
            {"key": "auto_approval"},
            {"$set": {"value": is_auto_approval}},
            upsert=True
        )

        return JsonResponse({"message": "Auto-approval setting updated successfully"}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
@api_view(["GET"])
def get_auto_approval_status(request):
    """
    API to check if auto-approval is enabled.
    """
    try:
        auto_approval_setting = superadmin_collection.find_one({"key": "auto_approval"})
        is_auto_approval = auto_approval_setting.get("value", False) if auto_approval_setting else False
        return JsonResponse({"is_auto_approval": is_auto_approval}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def review_job(request, job_id):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            action = data.get("action")
            if action not in ["approve", "reject"]:
                return JsonResponse({"error": "Invalid action"}, status=400)
            job = job_collection.find_one({"_id": ObjectId(job_id)})
            if not job:
                return JsonResponse({"error": "Job not found"}, status=404)
            if action == "approve":
                job_collection.update_one(
                    {"_id": ObjectId(job_id)},
                    {
                        "$set": {
                            "is_publish": True,
                            "updated_at": datetime.now(),
                        }
                    },
                )
                return JsonResponse(
                    {"message": "Job approved and published successfully"}, status=200
                )
            elif action == "reject":
                job_collection.update_one(
                    {"_id": ObjectId(job_id)},
                    {
                        "$set": {
                            "is_publish": False,
                            "updated_at": datetime.now(),
                        }
                    },
                )
                return JsonResponse(
                    {"message": "Job rejected successfully"}, status=200
                )
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)
    
@csrf_exempt
def get_published_jobs(request):
    """
    Fetch all jobs with is_publish set to True (Approved).
    """
    try:
        published_jobs = job_collection.find({"is_publish": True})  # Ensures only approved jobs are fetched
        job_list = []
        for job in published_jobs:
            job["_id"] = str(job["_id"])  # Convert ObjectId to string
            job_list.append(job)
        return JsonResponse({"jobs": job_list}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    
@csrf_exempt
def get_job_by_id(request, job_id):
    """
    Fetch a single job by its ID.
    """
    try:
        job = job_collection.find_one({"_id": ObjectId(job_id)})
        if not job:
            return JsonResponse({"error": "Job not found"}, status=404)

        job["_id"] = str(job["_id"])  # Convert ObjectId to string
        return JsonResponse({"job": job}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def update_job(request, job_id):
    """
    Update a job by its ID.
    """
    if request.method == 'PUT':
        try:
            data = json.loads(request.body)

            # Convert job_id to ObjectId
            job_object_id = ObjectId(job_id)

            # Find the existing job
            job = job_collection.find_one({"_id": job_object_id})
            if not job:
                return JsonResponse({"error": "Job not found"}, status=404)

            # Ensure _id is not modified
            data.pop('_id', None)

            # Add or update the 'edited' field
            data['edited'] = data.get('edited', True)  # Default to True if not provided

            # Update the job document
            job_collection.update_one({"_id": job_object_id}, {"$set": data})

            # Fetch updated job and convert ObjectId fields to strings
            updated_job = job_collection.find_one({"_id": job_object_id})
            updated_job["_id"] = str(updated_job["_id"])

            # Ensure all ObjectId fields (like admin_id, item_id) are converted to strings
            if "admin_id" in updated_job and isinstance(updated_job["admin_id"], ObjectId):
                updated_job["admin_id"] = str(updated_job["admin_id"])
            if "item_id" in updated_job and isinstance(updated_job["item_id"], ObjectId):
                updated_job["item_id"] = str(updated_job["item_id"])

            return JsonResponse({"job": updated_job}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid method"}, status=405)

@csrf_exempt
def delete_job(request, job_id):
    """
    Delete a job by its ID and remove it from students' saved jobs.
    """
    if request.method == 'DELETE':
        try:
            # Check if the job exists
            job = job_collection.find_one({"_id": ObjectId(job_id)})
            if not job:
                return JsonResponse({"error": "Job not found"}, status=404)

            # Delete the job from the job collection
            job_collection.delete_one({"_id": ObjectId(job_id)})

            # Update students' saved jobs
             # Update students' saved jobs
            student_collection.update_many(
                {"saved_jobs": job_id},
                {"$pull": {"saved_jobs": job_id}}
            )

            # Update students' applied jobs
            student_collection.update_many(
                {"applied_jobs.job_id": job_id},
                {"$pull": {"applied_jobs": {"job_id": job_id}}}
            )

            return JsonResponse({"message": "Job deleted successfully"}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid method"}, status=405)

# ============================================================== ACHIEVEMENTS ======================================================================================

@csrf_exempt
@api_view(['POST'])
def post_achievement(request):
    try:
        # Decode the JWT token
        role = request.POST.get("role")
        print(role)
        userid = request.POST.get("userId")
          # Extract admin_id from token
        if not userid:
            return Response({"error": "user_id not found"}, status=status.HTTP_401_UNAUTHORIZED)

        # Get text data from request
        name = request.POST.get("name")
        achievement_description = request.POST.get("achievement_description")  # Corrected field name
        achievement_type = request.POST.get("achievement_type")
        company_name = request.POST.get("company_name")
        date_of_achievement = request.POST.get("date_of_achievement")
        batch = request.POST.get("batch")

        # Check if an image was uploaded
        if "photo" in request.FILES:
            image_file = request.FILES["photo"]
            # Convert the image to base64
            image_base64 = base64.b64encode(image_file.read()).decode('utf-8')
        else:
            image_base64 = None  # Photo is optional

        # Prepare the document to insert
        achievement_data = {
            "name": name,
            "achievement_description": achievement_description,  # Corrected field name
            "achievement_type": achievement_type,
            "company_name": company_name,
            "date_of_achievement": date_of_achievement,
            "batch": batch,
            "photo": image_base64,  # Store as base64
            "admin_id": userid,  # Save the admin_id from the token
            "created_by": role,
            "is_publish": True,  # Directly publish as no approval needed
            "updated_at": datetime.now()
        }

        # Insert into MongoDB
        achievement_collection.insert_one(achievement_data)

        return Response({"message": "Achievement stored successfully"}, status=status.HTTP_201_CREATED)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@csrf_exempt
def manage_achievements(request):
    if request.method == 'GET':
        jwt_token = request.COOKIES.get('jwt')
        
        if not jwt_token:
            return JsonResponse({'error': 'JWT token missing'}, status=401)

        try:
            decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            role = decoded_token.get('role')
            admin_user = decoded_token.get('admin_user') if role == "admin" else decoded_token.get('superadmin_user')

            if not admin_user:
                return JsonResponse({"error": "Invalid token"}, status=401)

            # Fetch achievements from MongoDB based on admin_user
            achievements = achievement_collection.find({"admin_id": admin_user} if role == "admin" else {})
            achievement_list = []
            for achievement in achievements:
                achievement["_id"] = str(achievement["_id"])  # Convert ObjectId to string
                achievement_list.append(achievement)

            return JsonResponse({"achievements": achievement_list}, status=200)

        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'JWT token has expired'}, status=401)
        except jwt.InvalidTokenError as e:
            return JsonResponse({'error': f'Invalid JWT token: {str(e)}'}, status=401)
        except Exception as e:
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
@csrf_exempt
def update_achievement(request, achievement_id):
    """
    Update an achievement by its ID, including image updates.
    """
    if request.method == 'PUT':
        try:
            data = json.loads(request.body)
            achievement = achievement_collection.find_one({"_id": ObjectId(achievement_id)})

            if not achievement:
                return JsonResponse({"error": "Achievement not found"}, status=404)

            # Remove _id if present in the update data
            if '_id' in data:
                del data['_id']

            # Check if an image was uploaded (optional)
            if "photo" in request.FILES:
                image_file = request.FILES["photo"]
                image_base64 = base64.b64encode(image_file.read()).decode('utf-8')
                data["photo"] = image_base64  # Store the updated image as base64

            # Update the achievement in MongoDB
            data["updated_at"] = datetime.now()  # Update timestamp
            achievement_collection.update_one({"_id": ObjectId(achievement_id)}, {"$set": data})

            # Fetch updated achievement
            updated_achievement = achievement_collection.find_one({"_id": ObjectId(achievement_id)})
            updated_achievement["_id"] = str(updated_achievement["_id"])  # Convert ObjectId to string

            return JsonResponse({"achievement": updated_achievement}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid method"}, status=405)
    
@csrf_exempt
def get_achievements(request):
    try:
        achievements = achievement_collection.find()
        achievement_list = [
            {**achievement, "_id": str(achievement["_id"])}  # Convert ObjectId to string
            for achievement in achievements
        ]
        return JsonResponse({"achievements": achievement_list}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def delete_achievement(request, achievement_id):
    """
    Delete an achievement by its ID.
    """
    if request.method == 'DELETE':
        try:
            result = achievement_collection.delete_one({"_id": ObjectId(achievement_id)})

            if result.deleted_count == 0:
                return JsonResponse({"error": "Achievement not found"}, status=404)

            return JsonResponse({"message": "Achievement deleted successfully"}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid method"}, status=405)

@csrf_exempt
def get_published_achievements(request):
    try:
        published_achievements = achievement_collection.find({"is_publish": True})
        achievement_list = [
            {**achievement, "_id": str(achievement["_id"])}  # Convert ObjectId to string
            for achievement in published_achievements
        ]
        return JsonResponse({"achievements": achievement_list}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    
# ============================================================== INTERNSHIP ======================================================================================

@csrf_exempt
def post_internship(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        try:
            role = data.get('role')
            userid = data.get('userId')
            auto_approval_setting = superadmin_collection.find_one({"key": "auto_approval"})
            is_auto_approval = auto_approval_setting.get("value", False) if auto_approval_setting else False

            is_publish = None

            if role == 'admin':
                if is_auto_approval:
                    is_publish = True

            elif role == 'superadmin':
                is_publish = True

            application_deadline_str = data.get('application_deadline')

            # Convert application_deadline to a timezone-aware datetime
            try:
                application_deadline = datetime.strptime(application_deadline_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                return JsonResponse({"error": "Invalid date format for application_deadline. Use YYYY-MM-DD."}, status=400)

            now = datetime.now(timezone.utc)
            current_status = "active" if application_deadline >= now else "expired"

            # Ensure required fields are present
            required_fields = [
                'title', 'company_name', 'location', 'duration', 'stipend',
                'application_deadline', 'skills_required', 'job_description',
                'company_website', 'internship_type'
            ]
            for field in required_fields:
                if field not in data:
                    return JsonResponse({"error": f"Missing required field: {field}"}, status=400)

            # Prepare internship data for insertion
            internship_post = {
                "internship_data": {
                    "title": data['title'],
                    "company_name": data['company_name'],
                    "location": data['location'],
                    "duration": data['duration'],
                    "stipend": data['stipend'],
                    "application_deadline": application_deadline,
                    "required_skills": data['skills_required'],
                    "education_requirements": data.get('education_requirements', ""),
                    "job_description": data['job_description'],
                    "company_website": data['company_website'],
                    "job_link": data.get('job_link', ""),
                    "internship_type": data['internship_type'],
                },
                "admin_id" if role == "admin" else "superadmin_id": userid,
                "is_publish": is_publish,
                "status": current_status,
                "updated_at": datetime.utcnow()
            }

            # Insert into MongoDB
            internship_collection.insert_one(internship_post)

            # Return success response
            return JsonResponse({"message": "Internship posted successfully, awaiting approval."}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method. Only POST is allowed."}, status=405)

@csrf_exempt
def manage_internships(request):
    if request.method == 'GET':
        # Retrieve JWT token from Authorization Header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return JsonResponse({'error': 'No token provided'}, status=401)

        jwt_token = auth_header.split(" ")[1]

        try:
            # Decode JWT token
            decoded_token = jwt.decode(jwt_token, 'secret', algorithms=["HS256"])
            role = decoded_token.get('role')
            admin_user = decoded_token.get('admin_user') if role == "admin" else decoded_token.get('superadmin_user')

            if not admin_user:
                return JsonResponse({"error": "Invalid token"}, status=401)

            # Fetch internships from MongoDB based on admin_user
            internships = internship_collection.find({"admin_id": admin_user} if role == "admin" else {})
            internship_list = []
            for internship in internships:
                internship["_id"] = str(internship["_id"])  # Convert ObjectId to string
                internship_list.append(internship)

            return JsonResponse({"internships": internship_list}, status=200)

        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'JWT token has expired'}, status=401)
        except jwt.InvalidTokenError as e:
            return JsonResponse({'error': f'Invalid JWT token: {str(e)}'}, status=401)
        except Exception as e:
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def get_published_internships(request):
    try:
        internship_list = []
        published_internships = internship_collection.find({"is_publish": True})
        for internship in published_internships:
            internship["_id"] = str(internship["_id"])
            internship_list.append(internship)
        return JsonResponse({"internships": internship_list}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def review_internship(request, internship_id):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            action = data.get("action")
            if action not in ["approve", "reject"]:
                return JsonResponse({"error": "Invalid action"}, status=400)

            internship = internship_collection.find_one({"_id": ObjectId(internship_id)})
            if not internship:
                return JsonResponse({"error": "Internship not found"}, status=404)

            is_publish = True if action == "approve" else False
            internship_collection.update_one(
                {"_id": ObjectId(internship_id)},
                {"$set": {"is_publish": is_publish, "updated_at": datetime.now()}}
            )

            message = "Internship approved and published successfully" if is_publish else "Internship rejected successfully"
            return JsonResponse({"message": message}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def get_internships(request):
    try:
        internships = internship_collection.find()
        internship_list = []
        
        for internship in internships:
            # Convert ObjectId to string
            internship["_id"] = str(internship["_id"])

            # Convert application_deadline to date format if it's a string
            if "application_deadline" in internship and internship["application_deadline"]:
                deadline = internship["application_deadline"]
                
                try:
                    # Try parsing as full datetime format
                    formatted_deadline = datetime.strptime(deadline, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d")
                except ValueError:
                    try:
                        # Try parsing as plain date format
                        formatted_deadline = datetime.strptime(deadline, "%Y-%m-%d").strftime("%Y-%m-%d")
                    except ValueError:
                        # If parsing fails, keep original value
                        formatted_deadline = deadline
                
                internship["application_deadline"] = formatted_deadline  # Update with formatted date

            # Fetch admin details using admin_id
            admin_id = internship.get("admin_id")
            admin_name = "Unknown Admin"


            if admin_id:
                try:
                    admin = admin_collection.find_one({"_id": ObjectId(admin_id)})  # Convert to ObjectId
                    if admin:
                        admin_name = admin.get("name", "Unknown Admin")
                except Exception as e:
                    print("Error fetching admin:", e)

            # Add admin name to the response
            internship["admin_name"] = admin_name

            internship_list.append(internship)

        return JsonResponse({"internships": internship_list}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

@csrf_exempt
def get_internship_id(request, internship_id):
    """
    Get an internship by its ID.
    """
    if request.method == 'GET':
        try:
            internship = internship_collection.find_one({"_id": ObjectId(internship_id)})
            if not internship:
                return JsonResponse({"error": "Internship not found"}, status=404)

            internship["_id"] = str(internship["_id"])  # Convert ObjectId to string

            # Convert application_deadline to only date format (YYYY-MM-DD)
            if "application_deadline" in internship and internship["application_deadline"]:
                if isinstance(internship["application_deadline"], datetime):  # If it's a datetime object
                    internship["application_deadline"] = internship["application_deadline"].strftime("%Y-%m-%d")
                else:  # If it's a string, ensure it's correctly formatted
                    try:
                        internship["application_deadline"] = datetime.strptime(internship["application_deadline"], "%Y-%m-%dT%H:%M:%S").strftime("%Y-%m-%d")
                    except ValueError:
                        pass  # Ignore if the format is unexpected

            return JsonResponse({"internship": internship}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid method"}, status=405)

    
@csrf_exempt
def delete_internship(request, internship_id):
    """
    Delete an internship by its ID.
    """
    if request.method == 'DELETE':
        try:
            internship = internship_collection.find_one({"_id": ObjectId(internship_id)})
            if not internship:
                return JsonResponse({"error": "Internship not found"}, status=404)

            internship_collection.delete_one({"_id": ObjectId(internship_id)})
            return JsonResponse({"message": "Internship deleted successfully"}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid method"}, status=405)

@csrf_exempt
def update_internship(request, internship_id):
    """
    Update an internship by its ID.
    """
    if request.method == 'PUT':
        try:
            data = json.loads(request.body)
            internship = internship_collection.find_one({"_id": ObjectId(internship_id)})
            if not internship:
                return JsonResponse({"error": "Internship not found"}, status=404)

            # Exclude the _id field from the update
            if '_id' in data:
                del data['_id']

            # Separate the 'edited' field from the rest of the data
            edited_value = data.pop("edited", None)

            # Prepare the update data for nested fields
            update_data = {"$set": {f"internship_data.{key}": value for key, value in data.items()}}

            # If 'edited' is provided, add it to the root level update
            if edited_value is not None:
                update_data["$set"]["edited"] = edited_value

            internship_collection.update_one({"_id": ObjectId(internship_id)}, update_data)
            updated_internship = internship_collection.find_one({"_id": ObjectId(internship_id)})
            updated_internship["_id"] = str(updated_internship["_id"])  # Convert ObjectId to string
            return JsonResponse({"internship": updated_internship}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid method"}, status=405)

@csrf_exempt
def manage_jobs(request):
    if request.method == 'GET':
        jwt_token = request.COOKIES.get('jwt')
        print(jwt_token)
        if not jwt_token:
            return JsonResponse({'error': 'JWT token missing'}, status=401)

        try:
            decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            admin_user = decoded_token.get('admin_user')

            # Fetch jobs from MongoDB based on admin_user
            jobs = job_collection.find({'admin_id': admin_user})
            jobs_list = []
            for job in jobs:
                job['_id'] = str(job['_id'])
                jobs_list.append(job)

            return JsonResponse({'jobs': jobs_list}, status=200)

        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'JWT token has expired'}, status=401)
        except jwt.InvalidTokenError as e:
            return JsonResponse({'error': f'Invalid JWT token: {str(e)}'}, status=401)
        except Exception as e:
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)
       
@csrf_exempt
def get_jobs(request):
    if request.method == 'GET':
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return JsonResponse({'error': 'JWT token missing or invalid'}, status=401)

        jwt_token = auth_header.split(" ")[1]

        try:
            decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])  
            admin_user = decoded_token.get('admin_user')

            jobs = job_collection.find({'admin_id': admin_user})
            jobs_list = []

            for job in jobs:
                job['_id'] = str(job['_id'])
                job['type'] = 'job' 
                jobs_list.append(job)

            internships = internship_collection.find({'admin_id': admin_user})
            for internship in internships:
                internship['_id'] = str(internship['_id'])
                internship['type'] = 'internship'
                jobs_list.append(internship)

            return JsonResponse({'jobs': jobs_list}, status=200)

        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'JWT token has expired'}, status=401)
        except jwt.InvalidTokenError as e:
            return JsonResponse({'error': f'Invalid JWT token: {str(e)}'}, status=401)
        except Exception as e:
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

#===================================================================Admin-Mails====================================================================== 

@csrf_exempt
def get_admin_inbox(request):
    if request.method == "GET":
        # Retrieve JWT token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'JWT token missing'}, status=401)

        jwt_token = auth_header.split(' ')[1]

        try:
            # Decode the JWT token
            decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            admin_id = decoded_token.get('admin_user')

            # Check if admin_id is present in the token
            if not admin_id:
                return JsonResponse({"error": "Invalid token: No admin_id"}, status=401)

            # Fetch jobs, internships, achievements, and study materials from MongoDB where admin_id matches
            jobs = list(job_collection.find({"admin_id": admin_id}))
            internships = list(internship_collection.find({"admin_id": admin_id}))
            achievements = list(achievement_collection.find({"admin_id": admin_id}))
            study_materials = list(study_material_collection.find({"admin_id": admin_id}))

            # Convert MongoDB ObjectId to string for JSON serialization
            def convert_objectid_to_str(items):
                for item in items:
                    item["_id"] = str(item["_id"])  # Convert ObjectId to string
                return items

            return JsonResponse({
                "jobs": convert_objectid_to_str(jobs),
                "internships": convert_objectid_to_str(internships),
                "achievements": convert_objectid_to_str(achievements),
                "study_materials": convert_objectid_to_str(study_materials),
            }, safe=False, status=200)

        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Token has expired"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Invalid token"}, status=401)
        except Exception as e:
            return JsonResponse({"error": f"Server error: {str(e)}"}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)


@csrf_exempt
def submit_feedback(request):
    if request.method == "POST":
        try:
            # Decode the JWT token
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return JsonResponse({'error': 'Invalid token'}, status=401)

            token = auth_header.split(' ')[1]
            decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

            # Parse the request body
            data = json.loads(request.body)
            item_id = data.get('item_id')
            item_type = data.get('item_type')
            feedback = data.get('feedback')

            if not item_id or not item_type or not feedback:
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            # Determine the collection based on item_type
            if item_type == "job":
                collection = job_collection
            elif item_type == "internship":
                collection = internship_collection
            elif item_type == "achievement":
                collection = achievement_collection
            else:
                return JsonResponse({'error': 'Invalid item type'}, status=400)

            # Fetch the item data
            item_data = collection.find_one({'_id': ObjectId(item_id)})
            if not item_data:
                return JsonResponse({'error': f'Invalid item_id: {item_type.capitalize()} not found'}, status=404)

            admin_id = item_data.get('admin_id')
            item_name = item_data.get('job_data', {}).get('title') or item_data.get('internship_data', {}).get('title') or item_data.get('name')

            if not admin_id:
                return JsonResponse({'error': 'admin_id not found for the provided item'}, status=404)

            # Store the feedback in the Reviews collection
            review_document = {
                'admin_id': admin_id,
                'item_id': item_id,
                'item_name': item_name,
                'item_type': item_type,
                'feedback': feedback,
                'timestamp': datetime.now().isoformat()
            }
            reviews_collection.insert_one(review_document)

            return JsonResponse({'message': 'Feedback submitted successfully'}, status=200)

        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Token has expired"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Invalid token"}, status=401)
        except Exception as e:
            return JsonResponse({"error": f"Server error: {str(e)}"}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)


# ============================================================== STUDY MATERIALS ======================================================================================

@csrf_exempt
def post_study_material(request):
    if request.method == 'POST':
        try:
            # Get JWT token from Authorization Header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith("Bearer "):
                return JsonResponse({"error": "No token provided"}, status=401)

            jwt_token = auth_header.split(" ")[1]

            # Decode JWT token
            try:
                decoded_token = jwt.decode(jwt_token, 'secret', algorithms=["HS256"])
                print("Decoded Token:", decoded_token)  # Debugging: Check the decoded token
            except jwt.ExpiredSignatureError:
                return JsonResponse({"error": "Token expired"}, status=401)
            except jwt.InvalidTokenError:
                return JsonResponse({"error": "Invalid token"}, status=401)

            role = decoded_token.get('role')
            auto_approval_setting = superadmin_collection.find_one({"key": "auto_approval"})
            is_auto_approval = auto_approval_setting.get("value", False) if auto_approval_setting else False

            if role == 'admin':
                admin_id = decoded_token.get('admin_user')  
                if not admin_id:
                    return JsonResponse({"error": "Invalid token"}, status=401)
                is_publish = True
            
            elif role == 'superadmin':
                superadmin_id = decoded_token.get('superadmin_user')
                if not superadmin_id:
                    return JsonResponse({"error": "Invalid token"}, status=401)
                is_publish = True

            # Parse incoming JSON data
            data = json.loads(request.body)

            # Ensure required fields are present
            required_fields = ['title', 'description', 'category', 'text_content']
            for field in required_fields:
                if field not in data:
                    return JsonResponse({"error": f"Missing required field: {field}"}, status=400)

            study_material_post = {
                "study_material_data": {
                    "title": data['title'],
                    "description": data['description'],
                    "category": data['category'],
                    "text_content": data['text_content'],
                    "link":data['link']
                },
                "admin_id" if role == "admin" else "superadmin_id": admin_id if role == "admin" else superadmin_id,
                "is_publish": is_publish,
                "updated_at": datetime.utcnow()
            }

            # Insert into MongoDB
            study_material_collection.insert_one(study_material_post)

            return JsonResponse({"message": "Study Material posted successfully"}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format."}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method. Only POST is allowed."}, status=405)

@csrf_exempt
def manage_study_materials(request):
    if request.method == 'GET':
        # Retrieve JWT token from Authorization Header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return JsonResponse({'error': 'No token provided'}, status=401)

        jwt_token = auth_header.split(" ")[1]

        try:
            # Decode JWT token
            decoded_token = jwt.decode(jwt_token, 'secret', algorithms=["HS256"])
            role = decoded_token.get('role')
            admin_user = decoded_token.get('admin_user') if role == "admin" else decoded_token.get('superadmin_user')

            if not admin_user:
                return JsonResponse({"error": "Invalid token"}, status=401)

            # Fetch study materials from MongoDB based on admin_user
            study_materials = study_material_collection.find({"admin_id": admin_user} if role == "admin" else {})
            study_material_list = []
            for study in study_materials:
                study["_id"] = str(study["_id"])  # Convert ObjectId to string
                study_material_list.append(study)

            return JsonResponse({"study_materials": study_material_list}, status=200)

        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'JWT token has expired'}, status=401)
        except jwt.InvalidTokenError as e:
            return JsonResponse({'error': f'Invalid JWT token: {str(e)}'}, status=401)
        except Exception as e:
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def get_study_material_by_id(request, study_material_id):
    """
    Fetch a single study material by its ID.
    """
    try:
        study_material = study_material_collection.find_one({"_id": ObjectId(study_material_id)})
        if not study_material:
            return JsonResponse({"error": "Study material not found"}, status=404)

        study_material["_id"] = str(study_material["_id"])  # Convert ObjectId to string
        return JsonResponse({"study_material": study_material}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def update_study_material(request, study_material_id):
    """
    Update a study material by its ID.
    """
    if request.method == 'PUT':
        try:
            data = json.loads(request.body)
            study_material = study_material_collection.find_one({"_id": ObjectId(study_material_id)})
            if not study_material:
                return JsonResponse({"error": "Study material not found"}, status=404)

            # Exclude the _id field from the update
            if '_id' in data:
                del data['_id']

            study_material_collection.update_one({"_id": ObjectId(study_material_id)}, {"$set": data})
            updated_study_material = study_material_collection.find_one({"_id": ObjectId(study_material_id)})
            updated_study_material["_id"] = str(updated_study_material["_id"])  # Convert ObjectId to string
            return JsonResponse({"study_material": updated_study_material}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid method"}, status=405)

@csrf_exempt
def delete_study_material(request, study_material_id):
    """
    Delete a study material by its ID.
    """
    if request.method == 'DELETE':
        try:
            study_material = study_material_collection.find_one({"_id": ObjectId(study_material_id)})
            if not study_material:
                return JsonResponse({"error": "Study material not found"}, status=404)

            study_material_collection.delete_one({"_id": ObjectId(study_material_id)})
            return JsonResponse({"message": "Study material deleted successfully"}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid method"}, status=405)

@csrf_exempt
def fetch_review(request):
    """Extracts JWT, validates it, and fetches all review documents for the admin ID."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return JsonResponse({"error": "Unauthorized access"}, status=401)

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return JsonResponse({"error": "Token has expired"}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({"error": "Invalid token"}, status=401)

    admin_id = payload.get("admin_user")
    if not admin_id:
        return JsonResponse({"error": "Invalid token payload"}, status=401)

    print(f"Querying for admin_id: {admin_id}")  # Log the query
    reviews_cursor = reviews_collection.find({"admin_id": admin_id})  # Fetch all matching documents

    reviews_list = []
    for review in reviews_cursor:
        formatted_review = {
            "review_id": str(review["_id"]),  # Convert ObjectId to string
            "admin_id": review["admin_id"],
            "item_id": review["item_id"],
            "item_name": review.get("item_name", ""),  # Use `.get()` to avoid KeyError
            "item_type": review["item_type"],
            "feedback": review["feedback"],
            "timestamp": review["timestamp"],
        }
        reviews_list.append(formatted_review)

    if not reviews_list:
        return JsonResponse({"error": "Reviews not found"}, status=404)

    return JsonResponse({"reviews": reviews_list}, status=200, safe=False)  # Return as a list

#===============================================================Super-Admin-Mails====================================================================== 

@csrf_exempt
def get_contact_messages(request):
    if request.method == "GET":
        try:
            # Fetch all messages from the contact_us collection
            messages = list(contactus_collection.find({}, {"_id": 1, "name": 1, "contact": 1, "message": 1, "timestamp": 1}))

            # Format timestamp and convert `_id` to string
            for message in messages:
                message["_id"] = str(message["_id"])  # Convert ObjectId to string
                if "timestamp" in message and message["timestamp"]:
                    message["timestamp"] = message["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
                else:
                    message["timestamp"] = "N/A"

            return JsonResponse({"messages": messages}, status=200)

        except Exception as e:
            # Log the error and return a 500 response
            print(f"Error: {e}")
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def reply_to_message(request):
    """
    API to reply to a contact message.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            message_id = data.get("message_id")  # Message document _id
            reply_message = data.get("reply_message")  # Admin's reply text

            if not message_id or not reply_message:
                return JsonResponse({"error": "Message ID and reply message are required."}, status=400)

            # Update the existing message with the reply
            result = contactus_collection.update_one(
                {"_id": ObjectId(message_id)},
                {"$set": {"reply_message": reply_message}}
            )

            if result.modified_count == 0:
                return JsonResponse({"error": "Message not found or already updated."}, status=404)

            return JsonResponse({"success": "Reply sent successfully!"}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method."}, status=405)

@csrf_exempt
def get_jobs_with_admin(request):
    """
    Fetch all jobs and map them with admin names.
    """
    try:
        # Fetch all jobs from the jobs collection
        jobs = job_collection.find({}, {"_id": 1, "admin_id": 1, "job_data": 1, "updated_at": 1})

        job_list = []

        for job in jobs:
            job["_id"] = str(job["_id"])  # Convert ObjectId to string
            job["updated_at"] = job.get("updated_at", "N/A")

            # Fetch admin details using admin_id
            admin_id = job.get("admin_id")
            admin_name = "Unknown Admin"

            if admin_id:
                admin = admin_collection.find_one({"_id": ObjectId(admin_id)})
                if admin:
                    admin_name = admin.get("name", "Unknown Admin")

            # Append job details with mapped admin name
            job_list.append({
                "admin_name": admin_name,
                "message": f"{admin_name} posted a job",
                "job_data": job.get("job_data", {}),
                "timestamp": job["updated_at"]
            })

        return JsonResponse({"jobs": job_list}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    
@csrf_exempt
def get_achievements_with_admin(request):
    """
    Fetch all achievements and correctly map them with admin names.
    """
    try:
        achievements = achievement_collection.find({}, {"_id": 1, "user_id": 1, "achievement_description": 1, "achievement_type": 1, "company_name": 1, "date_of_achievement": 1, "updated_at": 1})

        achievement_list = []

        for achievement in achievements:
            achievement["_id"] = str(achievement["_id"])  # Convert ObjectId to string
            achievement["updated_at"] = achievement.get("updated_at", "N/A")

            # Fetch admin details using user_id
            admin_id = achievement.get("user_id")
            admin_name = "Unknown Admin"

            if admin_id:
                admin = admin_collection.find_one({"_id": ObjectId(admin_id)})
                if admin:
                    admin_name = admin.get("name", "Unknown Admin")

            # Append achievement details with mapped admin name
            achievement_list.append({
                "admin_name": admin_name,
                "message": f"{admin_name} posted an achievement",
                "achievement_data": {
                    "description": achievement.get("achievement_description", "No description"),
                    "type": achievement.get("achievement_type", "Unknown"),
                    "company": achievement.get("company_name", "Not specified"),
                    "date": achievement.get("date_of_achievement", "Unknown"),
                },
                "timestamp": achievement["updated_at"]
            })

        return JsonResponse({"achievements": achievement_list}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def get_internships_with_admin(request):
    """
    Fetch all internships and correctly map them with admin names.
    """
    try:
        internships = internship_collection.find({}, {"_id": 1, "admin_id": 1, "internship_data": 1, "updated_at": 1})

        internship_list = []

        for internship in internships:
            internship["_id"] = str(internship["_id"])  # Convert ObjectId to string
            internship["updated_at"] = internship.get("updated_at", "N/A")

            # Extract internship details from nested structure
            internship_data = internship.get("internship_data", {})

            # Fetch admin details using admin_id
            admin_id = internship.get("admin_id")
            admin_name = "Unknown Admin"

            if admin_id:
                admin = admin_collection.find_one({"_id": ObjectId(admin_id)})
                if admin:
                    admin_name = admin.get("name", "Unknown Admin")

            # Append internship details with all fields
            internship_list.append({
                "admin_name": admin_name,
                "message": f"{admin_name} posted an internship",
                "internship_data": {
                    "title": internship_data.get("title", "No title"),
                    "company": internship_data.get("company_name", "Not specified"),
                    "location": internship_data.get("location", "Unknown"),
                    "duration": internship_data.get("duration", "Unknown"),
                    "stipend": internship_data.get("stipend", "N/A"),
                    "deadline": internship_data.get("application_deadline", "N/A"),
                    "description": internship_data.get("job_description", "No description"),
                    "job_link": internship_data.get("job_link", "N/A"),
                    "education_requirements": internship_data.get("education_requirements", "N/A"),
                    "required_skills": internship_data.get("required_skills", []),
                    "internship_type": internship_data.get("internship_type", "N/A"),
                    "company_website": internship_data.get("company_website", "N/A"),
                    "status": internship_data.get("status", "N/A"),
                    "is_publish": internship_data.get("is_publish", False),
                },
                "timestamp": internship["updated_at"]
            })

        return JsonResponse({"internships": internship_list}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

    
@csrf_exempt
def get_study_materials_with_admin(request):
    try:
        study_materials = study_material_collection.find({}, {"_id": 1, "admin_id": 1, "study_material_data": 1, "updated_at": 1})

        study_material_list = []

        for material in study_materials:
            material["_id"] = str(material["_id"])
            material["updated_at"] = material.get("updated_at", "N/A")

            study_material_data = material.get("study_material_data", {})  # Ensure this exists

            admin_id = material.get("admin_id")
            admin_name = "Unknown Admin"

            if admin_id:
                admin = admin_collection.find_one({"_id": ObjectId(admin_id)})
                if admin:
                    admin_name = admin.get("name", "Unknown Admin")

            # Ensure all fields are correctly mapped
            study_material_list.append({
                "admin_name": admin_name,
                "message": f"{admin_name} shared a study material",
                "study_material_data": {
                    "title": study_material_data.get("title", "No title"),
                    "description": study_material_data.get("description", "No description"),
                    "category": study_material_data.get("category", "Uncategorized"),
                    "text_content": study_material_data.get("text_content", "No content available"),
                    "link": study_material_data.get("link", "N/A"),
                },
                "timestamp": material["updated_at"]
            })

        return JsonResponse({"study_materials": study_material_list}, status=200)
        print("Fetched study materials:", study_material_list)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

    
@csrf_exempt
def get_student_achievements(request):
    try:
        student_achievements = student_achievement_collection.find()
        achievement_list = []

        for achievement in student_achievements:
            student_name = achievement.get("name", "Unknown Student")
            achievement_desc = achievement.get("achievement_description", "No description")
            achievement_type = achievement.get("achievement_type", "Unknown Type")
            company = achievement.get("company_name", "Unknown Company")
            date_of_achievement = achievement.get("date_of_achievement", "Unknown Date")
            batch = achievement.get("batch", "Unknown Batch")
            photo = achievement.get("photo", None)  # Binary image data or URL

            message = f"{student_name} achieved {achievement_desc} in {achievement_type} on {date_of_achievement}"

            achievement_list.append({
                "student_name": student_name,
                "message": message,
                "achievement_data": {
                    "description": achievement_desc,
                    "type": achievement_type,
                    "company": company,
                    "date": date_of_achievement,
                    "batch": batch,
                    "photo": photo,
                    "is_approved": achievement.get("is_approved", False),
                },
                "timestamp": achievement.get("submitted_at", ""),
            })

        return JsonResponse({"student_achievements": achievement_list}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
      
#================================================================Profile=======================================================================================

@csrf_exempt
def get_admin_details(request, userId):
    if request.method == "GET":
        try:
            # Find the admin user by ID
            admin = admin_collection.find_one({"_id": ObjectId(userId)})

            if not admin:
                return JsonResponse(
                    {"error": "Admin with this ID does not exist"}, status=400
                )

            # Ensure profile_image field is correctly retrieved as a filename
            profile_image = admin.get("profile_image", "default.png")  # Default image if none

            # Prepare response data
            data = {
                "name": admin.get("name"),
                "email": admin.get("email"),
                "status": admin.get("status"),
                "created_at": str(admin.get("created_at")) if admin.get("created_at") else "N/A",
                "last_login": str(admin.get("last_login")) if admin.get("last_login") else "Never",
                "college_name": admin.get("college_name", "N/A"),
                "department": admin.get("department", "N/A"),
                "role": "admin",
                "profile_image": profile_image,  # Send only filename, not binary data
            }

            return JsonResponse({"message": "Admin details found", "data": data}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)
    
@csrf_exempt
def update_admin_profile(request, userId):
    if request.method == "PUT":
        try:
            # Parse JSON request body
            data = json.loads(request.body)

            # Find the admin user by ID
            admin = admin_collection.find_one({"_id": ObjectId(userId)})
            if not admin:
                return JsonResponse({"error": "Admin not found"}, status=404)

            # Validate request payload
            if "name" not in data or "profile_image" not in data:
                return JsonResponse({"error": "Missing required fields"}, status=400)

            # Prevent email from being changed
            data.pop("email", None)

            # Ensure only valid predefined images are used
            allowed_images = ["boy-1.png", "boy-2.png", "boy-3.png", "boy-4.png", "boy-5.png", "boy-6.png", "Girl-1.png", "Girl-2.png", "Girl-3.png", "Girl-4.png", "Girl-5.png"]
            if data["profile_image"] not in allowed_images:
                return JsonResponse({"error": "Invalid image selection"}, status=400)

            # Update only name and profile image
            updated_fields = {
                "name": data["name"],
                "profile_image": data["profile_image"]
            }

            admin_collection.update_one({"_id": ObjectId(userId)}, {"$set": updated_fields})

            return JsonResponse({"message": "Admin profile updated successfully"}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def get_superadmin_details(request, userId):
    if request.method == "GET":
        try:
            # Find the super admin user by ID
            superadmin = superadmin_collection.find_one({"_id": ObjectId(userId)})

            if not superadmin:
                return JsonResponse(
                    {"error": "Super Admin with this ID does not exist"}, status=400
                )

            # Handle profile image (Check if image is stored as a filename or binary)
            profile_image = ""
            if "profile_image" in superadmin:
                if isinstance(superadmin["profile_image"], bytes):
                    # Convert Binary image to Base64 format
                    profile_image = "data:image/jpeg;base64," + base64.b64encode(superadmin["profile_image"]).decode('utf-8')
                elif isinstance(superadmin["profile_image"], str):
                    # If stored as a filename, return it directly
                    profile_image = superadmin["profile_image"]

            # Prepare response data
            data = {
                "name": superadmin.get("name"),
                "email": superadmin.get("email"),
                "status": superadmin.get("status", "N/A"),
                "created_at": str(superadmin.get("created_at")) if superadmin.get("created_at") else "N/A",
                "last_login": str(superadmin.get("last_login")) if superadmin.get("last_login") else "Never",
                "college_name": superadmin.get("college_name", "N/A"),
                "department": superadmin.get("department", "N/A"),
                "role": "superadmin",
                "profile_image": profile_image,  # Send either Base64 or filename
            }

            return JsonResponse(
                {"message": "Super Admin details found", "data": data}, status=200
            )

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)

@api_view(['GET', 'PUT'])
def achievement_detail(request, achievement_id):
    try:
        # Convert ID to ObjectId
        object_id = ObjectId(achievement_id)
    except:
        return Response({"error": "Invalid Achievement ID"}, status=status.HTTP_400_BAD_REQUEST)

    # Fetch achievement from MongoDB
    achievement = achievement_collection.find_one({"_id": object_id})
    if not achievement:
        return Response({"error": "Achievement not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        # Convert MongoDB document to JSON response
        achievement["_id"] = str(achievement["_id"])  # Convert ObjectId to string
        return Response(achievement, status=status.HTTP_200_OK)

    elif request.method == 'PUT':
        # Update the achievement
        updated_data = request.data
        achievement_collection.update_one(
            {"_id": object_id},
            {"$set": updated_data}
        )
        return Response({"message": "Achievement updated successfully"}, status=status.HTTP_200_OK)



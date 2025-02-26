import requests
from django.http import JsonResponse
from pymongo import MongoClient
import json
from bs4 import BeautifulSoup
import nltk
from datetime import datetime
from nltk.tokenize import word_tokenize
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
import time
import os

# MongoDB Connection
client = MongoClient("mongodb+srv://ihub:ihub@cce.ksniz.mongodb.net/")
db = client["CCE"]

# RapidAPI Details
RAPIDAPI_KEY = "4c6f0f6fc5msh9ca8144c4f547fep16ac54jsndd5114267fd4"
RAPIDAPI_HOST = "jsearch.p.rapidapi.com"

def fetch_jobs_api(request):
    """Fetch jobs from RapidAPI and store in MongoDB in an organized format"""

    query = request.GET.get("query", "Software Developer in Tamil Nadu")  # Default search

    url = "https://jsearch.p.rapidapi.com/search"

    headers = {
        "X-RapidAPI-Key": RAPIDAPI_KEY,
        "X-RapidAPI-Host": RAPIDAPI_HOST
    }

    params = {
        "query": query,
        "page": "1",
        "num_pages": "1",
        "country": "in",
        "date_posted": "all",
        "language": "en"
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # Raises exception if API fails

        job_data = response.json().get("data", [])

        formatted_jobs = []
        for job in job_data:
            formatted_job = {
                "title": job.get("job_title", "N/A"),
                "company_name": job.get("employer_name", "N/A"),
                "company_website": job.get("employer_website", "N/A"),
                "job_description": job.get("job_description", "N/A"),
                "job_location": job.get("location", "N/A"),
                "salary_range": job.get("estimated_salary", "N/A"),
                "job_link": job.get("job_apply_link", "N/A"),
                "work_schedule": job.get("schedule_type", "N/A"),
                "selectedCategory": job.get("category", "IT & Development"),
                "selectedWorkType": job.get("job_employment_type", "Full-time"),
                "is_publish": True,
                "admin_id":"67a5ef2f731be13d58bb2e62",
                "status": "Active",
                "updated_at": datetime.now().isoformat(),
                "edited": "superadmin"  # Placeholder for now
            }

            # Store in MongoDB
            db.api_jobs.update_one(
                {"job_link": formatted_job["job_link"]},  # Unique Identifier
                {"$set": formatted_job},
                upsert=True
            )

            formatted_jobs.append(formatted_job)

        return JsonResponse({"message": "Jobs stored successfully!", "jobs": formatted_jobs}, status=200)

    except requests.exceptions.RequestException as e:
        return JsonResponse({"error": f"API request failed: {str(e)}"}, status=500)

def scrape_naukri_jobs(request):
    """Scrape jobs from Naukri and store in MongoDB"""

    query = request.GET.get("query", "Software Developer")
    location = request.GET.get("location", "India")

    # Format query for URL
    query_formatted = query.replace(" ", "-")
    location_formatted = location.replace(" ", "-")
    naukri_url = f"https://www.naukri.com/{query_formatted}-jobs-in-{location_formatted}"

    # **Configure Chrome for Render Deployment**
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run without UI (mandatory for Render)
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")  # Required for Render
    chrome_options.add_argument("--disable-dev-shm-usage")  # Fix crashes in cloud
    chrome_options.add_argument("--remote-debugging-port=9222")  # Debugging
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")  # Bypass bot detection
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

    # **Check if running on Render**
    if "RENDER" in os.environ:
        chrome_path = "/usr/bin/google-chrome"
        driver_path = "/usr/bin/chromedriver"
        chrome_options.binary_location = chrome_path
        service = Service(driver_path)
    else:
        service = Service(ChromeDriverManager().install())

    # **Start WebDriver**
    driver = webdriver.Chrome(service=service, options=chrome_options)
    driver.get(naukri_url)

    # **Wait Until Jobs Are Fully Loaded**
    try:
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "srp-jobtuple-wrapper")))
    except:
        driver.quit()
        return JsonResponse({"message": "Failed to load Naukri jobs!", "jobs": []}, status=500)

    jobs = []
    try:
        # **Find Job Listings**
        job_cards = driver.find_elements(By.CLASS_NAME, "srp-jobtuple-wrapper")
        if not job_cards:
            return JsonResponse({"message": "No jobs found on Naukri!", "jobs": []}, status=200)

        for job in job_cards:
            try:
                # **Extract Job Title & Link**
                title = job.find_element(By.XPATH, ".//h2/a").text.strip()
                job_link = job.find_element(By.XPATH, ".//h2/a").get_attribute("href")

                # **Extract Company Name**
                try:
                    company_name = job.find_element(By.XPATH, ".//span/a[contains(@class, 'comp-name')]").text.strip()
                except:
                    company_name = "Not Available"

                # **Extract Experience**
                try:
                    experience = job.find_element(By.XPATH, ".//span[contains(@class, 'exp')]").text.strip()
                except:
                    experience = "N/A"

                # **Extract Salary**
                try:
                    salary_range = job.find_element(By.XPATH, ".//span[contains(@class, 'salary')]").text.strip()
                except:
                    salary_range = "N/A"

                # **Extract Location**
                try:
                    job_location = job.find_element(By.XPATH, ".//span[contains(@class, 'location')]").text.strip()
                except:
                    job_location = "Not Specified"

                # **Extract Skills**
                try:
                    skills_elements = job.find_elements(By.XPATH, ".//ul[contains(@class, 'tags-gt')]/li")
                    required_skills = [skill.text.strip() for skill in skills_elements if skill.text.strip()]
                except:
                    required_skills = []

                # **Extract Job Description**
                try:
                    job_description = job.find_element(By.XPATH, ".//span[contains(@class, 'desc')]").text.strip()
                except:
                    job_description = "N/A"

                # **Format Job Data**
                formatted_job = {
                    "title": title,
                    "job_data": {
                        "company_name": company_name,
                        "job_description": job_description,
                        "required_skills": required_skills,
                        "experience_level": experience,
                        "salary_range": salary_range,
                        "job_location": job_location,
                        "job_link": job_link,
                        "selectedCategory": "IT & Development",
                        "selectedWorkType": "Full-time"
                    },
                    "is_publish": True,
                    "status": "Active",
                    "updated_at": datetime.utcnow().isoformat(),
                    "edited": "superadmin"
                }

                # **Store in MongoDB**
                db.scraped_jobs.update_one(
                    {"job_link": job_link},
                    {"$set": formatted_job},
                    upsert=True
                )

                jobs.append(formatted_job)

            except Exception as e:
                print(f"Error extracting job: {e}")

    finally:
        driver.quit()  # Close browser

    return JsonResponse({"message": "Naukri jobs scraped and stored successfully!", "jobs": jobs}, status=200)

nltk.download('punkt')

def search_jobs(request):
    """Search stored jobs using a natural-language prompt"""
    import nltk
    nltk.download('punkt')  # Ensure 'punkt' is downloaded before use
    from nltk.tokenize import word_tokenize

    user_query = request.GET.get("query", "").strip()

    if not user_query:
        return JsonResponse({"error": "Query is required!"}, status=400)

    # Tokenizing user input safely
    try:
        tokens = word_tokenize(user_query.lower())
    except Exception as e:
        return JsonResponse({"error": f"Failed to process query: {str(e)}"}, status=400)

    # Extract job category
    categories = ["software", "developer", "engineer", "data scientist"]
    matched_category = next((word for word in tokens if word in categories), "Software Developer")

    # Extract location
    locations = ["Tamil Nadu", "Chennai", "Bangalore", "Mumbai"]
    matched_location = next((word for word in tokens if word in locations), "Tamil Nadu")

    # Extract salary (if mentioned)
    salary = next((word for word in tokens if word.isdigit()), None)

    # Query MongoDB (API Jobs + Scraped Jobs)
    job_results = list(db.api_jobs.find({"title": {"$regex": matched_category, "$options": "i"}})) + \
                  list(db.scraped_jobs.find({"title": {"$regex": matched_category, "$options": "i"}}))

    # Filtering by location and salary
    if matched_location:
        job_results = [job for job in job_results if matched_location.lower() in job.get("location", "").lower()]

    if salary:
        job_results = [job for job in job_results if "salary" in job and int(job["salary"]) >= int(salary) * 100000]

    return JsonResponse({"jobs": job_results}, safe=False)
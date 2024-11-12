## PROJECT_NAME:
USERMANAGEMENT


## About This Project:
This project is a simple user management system built with Django, featuring essential user functionalities such as registration, login, profile management, and an admin interface for user and permission management.

## Features:
-User Authentication: Enables users to sign up, log in, and log out securely.
-User Profile Management: Each user has a profile page where they can view and manage their bio and profile picture.
-Admin Dashboard: Admin users have access to a dashboard to add, edit, and delete users, as well as manage permissions.
-Permissions: Role-based permissions restrict actions available to each user based on their assigned role.

## Technology:

- [![Static Badge]( https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
- [![Static Badge](https://img.shields.io/badge/Django-5.1.2-green.svg)](https://www.djangoproject.com/)
- [![Static Badge](https://img.shields.io/badge/DRF-3.14-red.svg)](https://www.django-rest-framework.org/)
- [![Static Badge](https://img.shields.io/badge/Git-2.40-orange.svg)]( https://git-scm.com/)
- [![Static Badge](https://img.shields.io/badge/GitHub-Repo-blue.svg)]( https://github.com/)
- [![Static Badge](https://img.shields.io/badge/SQLite-3-lightgrey.svg)](https://www.sqlite.org/)

## Project Structure:
```sh
staff_management/
├── accounts/  
│   ├──__pychache__  
│   ├──middlewares   
│   |    ├──auditlog_middleware.py
│   ├── migrations/        
│   ├── models
│   |   ├──__pycache__
│   |   ├──__init__.py
│   |   ├──accounts_model.py      
│   ├── __init__.py         
│   ├── admin.py            
│   ├── apps.py      
│   ├── permission.py
│   ├── serializer.py
│   ├── tests.py            
│   ├── urls.py            
│   └── views.py            
├── staff_management/         
│   ├── __init__.py         
│   ├── settings.py         
│   ├── urls.py             
│   └── wsgi.py             
└── manage.py 
├── db.sqlite3
├── Readme.md
├── requirements.txt              

```

## Installation Instructions:
1. Clone the Project:
````sh
git clone https://github.com/Chamnes-Nham/first-django.git
````
2. generate all of dependency:
```sh
pip install -r requirements.txt
```
2. Create and Activate the Virtual Environment:

````sh
Windows:
py -m venv .venv
source .venv/Scripts/activate
macOS/Linux:
sh
Copy code
python3 -m venv .venv
source .venv/bin/activate
Deactivate: Use deactivate to exit the virtual environment.
````
3. Set Up the Database:
````sh
Copy code
python manage.py makemigrations
python manage.py migrate
````
4. Create an Admin/Superuser:
````sh
Copy code
python manage.py createsuperuser
````
5. Install Required Libraries:
````sh
Copy code
pip install Pillow
````
6. Start the Server:
Navigate to the project directory and run:

```sh
Copy code
cd usermanagement
python manage.py runserver
```
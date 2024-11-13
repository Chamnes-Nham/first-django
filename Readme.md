## PROJECT_NAME:
STAFF MANAGEMENT SYSTEM


## About This Project:
The primary purpose of this project is to create a comprehensive staff management system using Django REST Framework that includes advanced features such as:

- User Authentication: Secure login, signup, and logout functionalities.
- Role-Based Access Control: Permissions tailored for different user roles (admin, staff, and customers).
- Detailed User Profile Management: Manage and view user details with custom fields.
- Stateless and Stateful Authentication: Implement both JWT-based token authentication and session-based stateful authentication.
- Advanced Features: Includes rate limiting, audit trails, and multi-factor authentication.
- Comprehensive API Documentation: Utilizing Spectacular Swagger for clear and interactive API exploration.


## Core Feature:
````sh
User Authentication: Signup, login, and logout functionality.
Role-Based Permissions: Custom permissions for admin, staff, and customer roles.
Detailed User Profiles: Profile views and management.
JWT and Stateful Authentication: Both token-based and session-based authentication.
Rate Limiting: Throttling for enhanced security.
API Documentation: Implemented using Spectacular Swagger.
````

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

2. Create and Activate the Virtual Environment:
````sh
Windows:
py -m venv .venv
source .venv/Scripts/activate
macOS/Linux:
python3 -m venv .venv
source .venv/bin/activate
Deactivate: Use 'deactivate' to exit the virtual environment.
````

3. generate all of dependency:
```sh
pip install -r requirements.txt
```

4. Set Up the Database or apply migrate:
````sh
python manage.py makemigrations
python manage.py migrate
````

5. Create an Admin/Superuser:
````sh
python manage.py createsuperuser
````

6. Install Required Libraries:
````sh
pip install Pillow
````

7. Start the Server:
Navigate to the project directory and run:
```sh
cd usermanagement
python manage.py runserver
```
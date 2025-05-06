--To Run the application:

--create a virtual environment inside the project folder

python -m venv env

--activate that virtual environment

env\Scripts\activate

--install the dependencies inside the activated virtual environment

pip install -r requirements.txt

--run the application:

python app.py

--On first run, an admin user will automatically be created:
- Email: admin@gmail.com
- Password: admin123



--To test the following endpoints use the Postman software or any HTTP client tool


API Endpoints:
--------------
POST /registerapi – Register a new user via JSON
POST /loginapi – Login and receive JWT token
GET /api/tasks – Get all tasks (JWT required)
POST /api/tasks – Create a new task (JWT required)
GET /api/tasks/<task_id> – Get a single task by ID (JWT required)
PUT /api/tasks/<task_id> – Update a task by ID (JWT required)
DELETE /api/tasks/<task_id> – Delete a task by ID (JWT required)
GET /api/profile – Get user profile and task summary (JWT required)
POST /api/help – Submit a help request 
Google Api(third party)


List of Sample payload of different functionalities:
-----------------------------------------------------

1. User Registration Endpoint

POST /registerapi

{
  "username": "simran",
  "email": "simran@gmail.com",
  "password": "Simran@123",
  "phone": "9876543210",
  "address":"delhi",
  "gender":"female" , 
  "role": "user"     // Optional: "user" or "admin"
}


2. User Login Endpoint

POST /loginapi

{
  "email": "simran@gmail.com",
  "password": "Simran@123123",

}


Response will contain JWT token like:

{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "role" :"user"
}


Use this token as Bearer in headers for the protected endpoints:

Authorization: Bearer <access_token>



TASKS ENDPOINTS (JWT Required)
=================================

3. Add New Task

POST /api/tasks


{
  "task_title": "New Task Title",
  "task_description": "A brief description of the task.",
  "task_priority": "High",  // Optional: Can be "Low", "Medium", or "High"
  "end_date": "2025-05-10"  // Optional: Date in YYYY-MM-DD format
}

4.Get all tasks

GET /api/tasks 

Authorization: Bearer <your_jwt_token>



5. Update Existing Task

PUT /api/tasks/<task_id> 

Authorization: Bearer <your_jwt_token>


{
  "task_title": "Updated Task Title",
  "task_description": "Updated description",
  "task_priority": "Low",
  "end_date": "2025-06-10",
  "progress": 70
}





6. Delete Tasks

DELETE /api/tasks/<task_id>

Authorization: Bearer <your_jwt_token>





7. Get User profile

GET /api/profile 

Authorization: Bearer <your_jwt_token>





8. Get help
POST /api/help 


Example:
{
  "name": "Simran",
  "email": "simran@gmail.com",
  "message": "I need help with the dashboard layout."
}






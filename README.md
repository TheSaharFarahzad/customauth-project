# CustomAuth App with Django REST Framework (DRF)

Welcome to the **CustomAuth App** built using **Django REST Framework (DRF)**. This project is designed to help you understand how to implement unit testing using **Pytest**. Follow the lessons to build your skills step-by-step.

Additionally, you can learn about **Django REST Framework (DRF)** and **Pytest** through these helpful Medium articles: [Python Unit Testing with Pytest](https://medium.com/@CodeWithSahar/Pytest)


## <a name='CodeVersions'></a>Code Versions

You can access each lesson's version of the code by clicking on the lesson below. Follow the instructions in the README file of each version:

- [**Lesson 1**: Setting Up Tests with Pytest](https://github.com/TheSaharFarahzad/library-app-medium/tree/lesson-1)  
   Learn how to install and configure Pytest in your Django project.

- [**Lesson 2**: Test Structure](https://github.com/TheSaharFarahzad/library-app-medium/tree/lesson-2)  
   Understand the structure of test directories and how to configure your project for test discovery.

- [**Lesson 3**: Writing Unit Tests](https://github.com/TheSaharFarahzad/library-app-medium/tree/lesson-3)  
   Write unit tests using Django’s APITestCase class and learn how to create your own test methods.

- [**Lesson 4**: Unittest Assertions](https://github.com/TheSaharFarahzad/library-app-medium/tree/lesson-4)  
   Learn about various assertion methods in Python’s Unittest framework for validating test results.

- [**Lesson 5**: Parameterized Testing](https://github.com/TheSaharFarahzad/library-app-medium/tree/lesson-5)  
   Explore how to write parameterized tests to run the same test with different inputs using the `parameterized` package.

- [**Lesson 6**: Skipping Tests: skip, skipif, and xfail](https://github.com/TheSaharFarahzad/library-app-medium/tree/lesson-6)  
   Learn how to use Pytest markers to skip tests, expect failures, and handle specific conditions.

- [**Lesson 7**: Using Fixtures](https://github.com/TheSaharFarahzad/library-app-medium/tree/lesson-7)  
   Implement fixtures in your tests to set up reusable test data and states across multiple test cases.

- [**Lesson 8**: Mocking in Tests](https://github.com/TheSaharFarahzad/library-app-medium/tree/lesson-8)  
   Understand how to use mocks and MagicMock to simulate objects and control behavior during tests.

- [**Lesson 9**: Running Tests](https://github.com/TheSaharFarahzad/library-app-medium/tree/lesson-9)  
   Discover how to run your tests with Pytest and optimize test execution with options like `--reuse-db` and `-n auto`.

- [**Lesson 10**: Generating Test Coverage Reports](https://github.com/TheSaharFarahzad/library-app-medium/tree/lesson-10)  
   Set up coverage reports to track your test coverage and improve the quality of your codebase.

- [**Lesson 11**: Best Practices for Unit Testing in Django](https://github.com/TheSaharFarahzad/library-app-medium/tree/lesson-11)  
   Learn best practices for writing unit tests in Django, including how to structure tests for maximum clarity and effectiveness.


## <a name='PreSetupInstructions'></a>Pre-Setup Instructions

### 1. <a name='CloneTheRepository'></a>Clone the Repository

Clone this repository to your local machine by running the following commands:

```bash
git clone https://github.com/TheSaharFarahzad/customauth-app.git
```

If you have already cloned the repository and want to update it, use the following command:

```bash
git pull origin master
```

### 2. <a name='SystemRequirements'></a>System Requirements

You'll need Python 3, python3-pip, python3-venv and PostgreSQL to be installed on your machine:


### 3. <a name='EnvironmentVariables'></a>Environment Variables

To manage sensitive information like database credentials, create a `.env` file in the root directory of your project and add your database credentials.

**NOTE**: Ensure this file is kept private and not tracked by Git.


### 4. <a name='PostgreSQL'></a>PostgreSQL

If your database is not set up, you'll need to configure it. You can use your favorite PostgreSQL admin tool or the command line interface (CLI):

Windows:
Open Command Prompt or PowerShell as administrator. Navigate to the PostgreSQL bin directory:
```bash
psql -U postgres
```

Linux:
Open the terminal. Switch to the PostgreSQL superuser and open PostgreSQL CLI:
```bash
sudo -u postgres psql
```

After accessing the PostgreSQL command line, use the following SQL commands to create a user, set passwords, configure the database, and manage privileges:

```sql

-- Create a new PostgreSQL user with a secure password:
-- Replace DATABASE_USER and DATABASE_PASSWORD with username and password in .env file.
CREATE USER DATABASE_USER WITH PASSWORD 'DATABASE_PASSWORD';

-- Create a new database and assign ownership to the new user:
-- Replace DATABASE_NAME with the name of your database.
CREATE DATABASE DATABASE_NAME OWNER DATABASE_USER;

-- Exit PostgreSQL:
\q

```

## <a name='Setup'></a>Setup

In this section we explain how you can set up the project with/without Docker.

### 1. <a name='SetupWithDocker'></a>Setup With Docker

### 2. <a name='SetupWithoutDocker'></a>Setup Without Docker

For maintaining a clean development environment, it's recommended to use a virtual environment for installing application-specific packages. There are various methods to create virtual environments, such as using Pipenv. Below is an example demonstrating how to set up a virtual environment using native tools:

Windows:
```bash
cd custom_user_project
python -m venv venv
```

Linux:
```bash
cd custom_user_project
python3 -m venv .venv
```

**NOTE**: Ensure you add your virtual environment directory to .gitignore to avoid committing unnecessary files to your repository.

Then, install the requirements in your virtual environment. But first, you need to activate the environment:

Windows:
```bash
venv\Scripts\activate
```

Linux:
```bash
source .venv/bin/activate
```

To install all requirements for local development, run the following command:

```bash
pip install -r requirements.txt
```

To deactivate the virtual environment you just need to run the following commands:

```bash
deactivate
```

## <a name='AccessTheApplication'></a>Access the Application

Once you have the application running, you can access it at [http://localhost:8000](http://localhost:8000).

## License

This project is licensed under the MIT License - see the LICENSE file for details.

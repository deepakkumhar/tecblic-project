# TECBLIC

## Index

- [TECBLIC](#tecblic)
  - [Index](#index)
    - [Introduction](#introduction)
    - [Installation](#installation)

### Introduction

- Supports latest version of Python i.e. Python 3.10.3  along with Django 4.1.3 :zap:
- Swagger integration available to prepare APIs documentation. :nail_care:

| Plugin | **Version**|
| ------ | ------ |
|  pip   |    22.2.2     |
| Python | 2.7.0-3.10.3  |
| Django | 2.2.8^=4.1.3 |
| Postgres |    11.6      |

### Installation

> ##### 1. Clone repository

```sh
git clone https://github.com/bhargavsonagara/tecblic-project
```

> ##### 2. If you not having pip,Django let's install

```sh
sudo easy_install pip
```

> ##### 3. Create certual environment and activate

```sh
pipenv shell
```

> ##### 4. Setup The Project

```sh
pipenv install -r requirements.txt
```

> ##### 5. Setting up your project secret key in .env

```sh
DEBUG=debug

DB_NAME=db name
DB_USER=user name
DB_PASSWORD=password  
DB_HOST=localhost
DB_PORT=port number

SECRET_KEY=enter django project secret key

BASE_URL=provide your host name ex. site.com 
SWAGGER_SERVER=provide your server path ex. http://site.com

example for localhost:
BASE_URL=127.0.0.1
SWAGGER_SERVER=http://127.0.0.1:8000/
```

> ##### 6. Create Database Manuanlly in PgAdmin
```sh
CREATE DATABASE <database_name>
```

> ##### 7. Setting up your database details in .env

```sh
DB_NAME=DATABASE_NAME
DB_USER=DATABASE_USER
DB_PASSWORD=DATABASE_PASSWORD
DB_HOST=HOST_NAME
DB_PORT=PORT_NUMBER
```

> ##### 8. Create tables by Django migration

```sh
python manage.py migrate
```

> ##### 9. Swagger UI will be available @ ``/swagger-ui/``

<br />



# udct-linuxproj

Project for the class 6 of the "Full Stack Developer" course from Udacity.
This is a README of a Flask App developed and hosted in a Linux Machine.

  Getting Started
  ===============

To access the App, you can use the following address:
http://lucaspassos.tk/

I've created a domain name to support the App.

The IP Address of the server: 18.220.5.84

  Prerequisites
  =============

- Python 2.7 or Python 3.3
- Flask
- OAuth2
- SQLAlchemy
- Flask WTF
- PostgreSQL

Running
=======

Create the DB using the following command: python models.py

Built With
==========

- Python
- Flask
- SQLAlchemy

Python Libraries
================

-  flask
-  sqlalchemy
-  flask_wtf
-  oauth2client
-  httplib2
-  json
-  requests

Modules & Structure
===================

- project.py - It contais akk the code to support the backend.
- models.py - The Data Model for the App
- fb_client_secrets.json - App and password for Facebook Auth
- client_secrets.json - App Data for Google+ Auth
- static/ - It contains all support files for the front end.
    - css/ - CSS files
    - js/ - Javascript files
  - templates/ - Contains all html files for the webpage

JSON ENDPOINTS
==============

You can use the following JSON endpoints to your application.

- /categories/JSON - List of all categories
- /categories/<category ID>/JSON - List of all items in the category ID mentioned
- /categories/<category id>/<item id>/JSON - List a single item mentioned in item id field.
  
PostgreSQL
==========
  
Used a PostgreSQL 9.5. The user catalog was created with permissions only to execute commands 
in the catalogdb database.
  
Apache2
=======
  
We are using an Apache2 Webserver to host the app.
  
Security
========
  
The following actions were performed in order to protect the server:
- Change the default port for SSH from 22 to 2200
- Disable the root remote acceess 
- Strict the use of RSA Keys to access the server
- Restrict the ports in the firewall using UFW
  

Versioning
==========

- 1.0 Init Version
- 1.1 Adding a JSON Endpoints
- 1.2 Using PostgreSQL


Authors
=======

- Lucas Passos - lucas_aaa.passos@hotmail.com

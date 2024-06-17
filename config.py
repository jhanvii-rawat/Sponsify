from dotenv import load_dotenv
import os
from app import app


load_dotenv()  ##to load information from .env 

app.config['SECRET_KEY']= os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI']= 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']= os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')




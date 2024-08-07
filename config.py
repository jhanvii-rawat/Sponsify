from dotenv import load_dotenv
import os

from flask import Flask

app = Flask(__name__)


load_dotenv()  ##to load information from .env 

app.config['SECRET_KEY']= os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI']=  "sqlite:///db.sqlite3"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']= False



from config import app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(50))
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin', 'sponsor', 'influencer'
    flagged = db.Column(db.Boolean, default=False)   

class Influencer(db.Model):
    __tablename__ = 'influencer'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(50))
    niche = db.Column(db.String(50), nullable=False)
    followers = db.Column(db.Integer, nullable=False)
    ad_requests = db.relationship('AdRequest', backref='influencer', lazy=True)

class Sponsor(db.Model):
    __tablename__ = 'sponsor'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    industry = db.Column(db.String(50), nullable=False)
    ad_requests = db.relationship('AdRequest', backref='sponsor', lazy=True)

class Campaign(db.Model):
    __tablename__ = 'campaign'
    id = db.Column(db.Integer, primary_key=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('sponsor.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    budget = db.Column(db.Float, nullable=False)
    ad_requests = db.relationship('AdRequest', backref='campaign', lazy=True, cascade='all, delete-orphan')

class AdRequest(db.Model):
    __tablename__ = 'adrequest'
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    influencer_id = db.Column(db.Integer, db.ForeignKey('influencer.id'))
    sponsor_id = db.Column(db.Integer, db.ForeignKey('sponsor.id'), nullable=False)
    messages = db.Column(db.Text)
    requirements = db.Column(db.Text, nullable=False)
    payment_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Pending')
    is_new_for_influencer = db.Column(db.Boolean, default=True)
    privacy = db.Column(db.String(20), nullable=False, default='Private')
    ad_interests = db.relationship('AdInterest', backref='adrequest', lazy=True, cascade='all, delete-orphan')

class AdInterest(db.Model):
    __tablename__ = 'ad_interest'
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    influencer_id = db.Column(db.Integer, db.ForeignKey('influencer.id'))
    sponsor_id = db.Column(db.Integer, db.ForeignKey('sponsor.id'), nullable=False)
    ad_id = db.Column(db.Integer, db.ForeignKey('adrequest.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Interest Sent')
    is_new_for_sponsor = db.Column(db.Boolean, default=False)
    privacy = db.Column(db.String(20), nullable=False, default='Private')



with app.app_context():
    db.create_all()
    #making admin if no admin exists in the database 
    admin= User.query.filter_by(role='admin').first()
    if not admin :
        password= generate_password_hash('admin')
        admin= User(username='admin',name='admin', role='admin', password= password)
        db.session.add(admin)
        db.session.commit()






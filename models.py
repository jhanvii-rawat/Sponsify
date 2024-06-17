from app import app
from flask_sqlalchemy import SQLAlchemy

db= SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True)
    pashash = db.Column(db.String(256), nullable= False)
    name = db.Column(db.String(64), nullable= False)
    is_admin = db.Column(db.Boolean, nullable= False, default= False)


class Sponsor(db.Model):
    __tablename__ = 'sponsors'
    id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    company_name = db.Column(db.String(150), nullable= False)
    industry = db.Column(db.String(150), nullable= False)
    budget = db.Column(db.Float, nullable= False)
    campaigns= db.relationship('Campaigns', backref='sponsers', lazy= True)

class Influencer(db.Model):
    __tablename__ = 'influencers'
    id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    category = db.Column(db.String(150), nullable= False)
    niche = db.Column(db.String(150), nullable= False)
    reach = db.Column(db.Integer, nullable= False)
    campaigns= db.relationship('Campaigns', backref='influncers', lazy= True)


class Campaign(db.Model):
    __tablename__ = 'campaigns'
    id = db.Column(db.Integer, primary_key=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('sponsors.id'))
    influencer_id = db.Column(db.Integer, db.ForeignKey('influencers.id'))
    title = db.Column(db.String(150), nullable= False)
    description = db.Column(db.Text, nullable= False)
    start_date = db.Column(db.Date, nullable= False)
    end_date = db.Column(db.Date, nullable= False)
    budget = db.Column(db.Float, nullable= False)
    visibility = db.Column(db.String(50))  # 'public', 'private'
    goals = db.Column(db.Text, nullable= False)
    adrequests= db.relationship('adrequest', backref='Campaigns',lazy= True)



class AdRequest(db.Model):
    __tablename__ = 'ad_requests'
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'))
    influencer_id = db.Column(db.Integer, db.ForeignKey('influencers.id'))
    messages = db.Column(db.Text, nullable= False)
    requirements = db.Column(db.Text, nullable= False)
    payment_amount = db.Column(db.Float, nullable= False)
    status = db.Column(db.String(50), nullable= False)
    campaigns= db.relationship('Campaigns', backref='ad_requests', lazy= True)


with app.app_context():
    db.create_all()
from flask import render_template, request, redirect, url_for, flash, get_flashed_messages, session, jsonify, send_file, make_response
from functools import wraps
from config import app
from models import  db, User, Sponsor, Influencer, Campaign, AdRequest, AdInterest
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from user_role import get_current_user
from datetime import datetime, date
from sqlalchemy.sql import func, extract
from decimal import Decimal
from io import StringIO
import csv



@app.route('/')
def index():
        return render_template('index.html')



@app.route('/login')
def login():
    return render_template('login.html')
        
  
@app.route('/login', methods=['POST'])
def login_post():
        
        username = request.form['username']
        password = request.form['password']
        

        if not username or not password:
            flash('Fill both the field')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if not user:
            flash('Username does not exist')
            return redirect(url_for('login'))
        
        if not check_password_hash(user.password, password):
            flash('wrong password!')
            return redirect(url_for('login'))
        
        session['user_id'] = user.id
        flash("Login Successfull",'Success')
        user = User.query.get(session['user_id'])
        if user.role == 'admin':
            return render_template('admin_dashboard.html', user=user)
        else:
            return render_template('home.html')
                
             
        

@app.route('/register_influencer', methods=['GET', 'POST'])
def register_influencer():
    if request.method == 'POST':
        username = request.form['username']
        name = request.form['name']
        niche = request.form['niche']
        followers = request.form['followers']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match') ##backend to frontend alert message
            return redirect(url_for('register_influencer'))

        if not followers.isdigit():
            flash('Followers must be a number')
            return redirect(url_for('register_influencer'))

        if User.query.filter_by(username=username).first() or Influencer.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register_influencer'))
        
        passhash= generate_password_hash(password)

        

        user = User(username=username, password=passhash, role='influencer', name=name)
        db.session.add(user)
        db.session.commit()

        influencer = Influencer(id=user.id, username=username,name=name, niche=niche, followers=int(followers))
        db.session.add(influencer)
        db.session.commit()

        flash('Registration successful')
        return redirect(url_for('login'))
    return render_template('register_influencer.html')

@app.route('/register_sponsor', methods=['GET', 'POST'])
def register_sponsor():
    if request.method == 'POST':
        username = request.form['username']
        company_name = request.form['company_name']
        industry = request.form['industry']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register_sponsor'))

        if User.query.filter_by(username=username).first() or Sponsor.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register_sponsor'))
        
        passhash= generate_password_hash(password)

        

        user = User(username=username,name=company_name, password=passhash, role='sponsor')
        db.session.add(user)
        db.session.commit()

        sponsor = Sponsor(id=user.id,username=username, company_name=company_name, industry=industry)
        db.session.add(sponsor)
        db.session.commit()

        flash('Registration successful')
        return redirect(url_for('login'))
    return render_template('register_sponsor.html')



##defining decorator for authentication below

def auth(func):
    #using the functools' wraps: it assigns some different name for func so that 
    #flask dosent throw an error of maping same function for different address
    @wraps(func)  
    def inner_auth(*args, **kwargs):
        if 'user_id' in session:
            return func(*args, **kwargs)
        else: 
            flash('Please login first')
            return redirect(url_for('login'))
    return inner_auth



#below pages need authentication hence @auth

@app.route('/home')
@auth
def home():
    user = User.query.get(session['user_id'])
    if user.role == 'admin':
        campaigns = Campaign.query.all()
        user = User.query.get(session['user_id'])
        return render_template('admin_dashboard.html', user=user, campaigns=campaigns)
    else:
        campaigns = Campaign.query.filter(Campaign.end_date >= date.today()).order_by(func.random()).limit(4).all()
        current_date = datetime.now().date()
        ad_requests = AdRequest.query.filter_by(privacy='Public').limit(3).all()
        top_influencers = Influencer.query.order_by(Influencer.followers.desc()).limit(3).all()
        top_sponsors = Sponsor.query.outerjoin(Campaign).group_by(Sponsor.id).order_by(func.count(Campaign.id).desc()).limit(3).all()
        
        # Get sponsors for the campaigns
        sponsors = {campaign.id: Sponsor.query.get(campaign.sponsor_id) for campaign in campaigns}
        
        return render_template('home.html', campaigns=campaigns, ad_requests=ad_requests, sponsors=sponsors, current_date=current_date, top_influencers=top_influencers, top_sponsors=top_sponsors, user=user)



@app.route('/profile_settings')
@auth
def profile_settings():
    user = User.query.get(session['user_id'])
    influencer = Influencer.query.get(session['user_id'])
    return render_template('profile_settings.html', user=user, influencer=influencer)


@app.route('/profile_settings', methods=['POST'])
@auth
def profile_settings_post():
    username = request.form.get('username')
    name = request.form.get('name')
    niche = request.form.get('niche')
    followers = request.form.get('followers')
    currentpassword = request.form.get('currentpassword')
    password = request.form.get('password')
    
    if not username or not currentpassword or not password:
        flash('Fill all the informatio!')
        return redirect(url_for('profile_settings'), influencer=influencer)
    
    user = User.query.get(session['user_id'])
    if not check_password_hash(user.password, currentpassword):
        flash ('Incorrect Passowrd!!')
        return redirect(url_for('profile_settings'), influencer=influencer)
    
    if username is user.username:
        new_username = User.query.filter_by(username=username).first()
        if new_username:
            flash('Username already taken')
            return redirect(url_for('profile_settings'), influencer= influencer)     
   
    influencer = Influencer.query.get(session['user_id'])
    
    new_password = generate_password_hash(password)
    user.username = username
    user.password = new_password
    user.name = name
    influencer.username = username
    influencer.name = username
    influencer.niche = niche
    influencer.followers = followers
    db.session.commit()
    flash('Changes Successful')
    return redirect(url_for('profile_settings'))






##generic search bar

@app.route('/search_navbar', methods=['GET'])
def search_navbar():
    keyword = request.args.get('keyword', '')
    filter_type = request.args.get('filter', '')
    niche = request.args.get('niche', '')

    companies = []
    influencers = []
    campaigns = []
    ad_requests = []

    if filter_type == 'company' or filter_type == '':
        companies = Sponsor.query.filter(Sponsor.company_name.ilike(f'%{keyword}%'))
        if niche:
            companies = companies.filter(Sponsor.industry.ilike(f'%{niche}%'))
        companies = companies.all()
    
    if filter_type == 'influencer' or filter_type == '':
        influencers = Influencer.query.filter(Influencer.username.ilike(f'%{keyword}%'))
        if niche:
            influencers = influencers.filter(Influencer.niche.ilike(f'%{niche}%'))
        influencers = influencers.all()
    
    if filter_type == 'campaign' or filter_type == '':
        campaigns = Campaign.query.filter(Campaign.name.ilike(f'%{keyword}%'))
        campaigns = campaigns.all()
    
    if filter_type == 'ad_request' or filter_type == '':
        ad_requests = AdRequest.query.filter(AdRequest.requirements.ilike(f'%{keyword}%'))
        if niche:
            ad_requests = ad_requests.filter(AdRequest.requirements.ilike(f'%{niche}%'))
        ad_requests = ad_requests.filter_by(privacy='Public').all()

    return render_template('search_navbar.html', keyword=keyword, filter_type=filter_type, niche=niche, companies=companies, influencers=influencers, campaigns=campaigns, ad_requests=ad_requests)


@app.route('/campaigns')
@auth
def campaigns():
    user = User.query.get(session['user_id'])
    if user.role == 'influencer':
        return render_template('campaigns_influencer.html', user=user)
    if user.role == 'sponsor':
        return render_template('campaigns_sponsor.html', user=user)
    if user.role == 'admin':
        return render_template('admin_dashboard.html', user=user)


@app.route('/logout')
@auth
def logout():
    session.pop('user_id')
    return redirect(url_for('login'))

@app.context_processor
def inject_user():
    return dict(get_current_user=get_current_user)



## admin routes

##defining decorator for authentication for admin below

def auth_admin(func):
    #using the functools' wraps: it assigns some different name for func so that 
    #flask dosent throw an error of maping same function for different address
    @wraps(func)  
    def inner_auth(*args, **kwargs):
        if 'user_id'not in session:
            flash('Please login first')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.role != 'admin':
            flash('You are not authorized to access this page')
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return inner_auth

@app.route('/admin_dashboard')
@auth_admin
def admin_dashboard():
    search = request.args.get('search', '')
    budget_order = request.args.get('budget_order', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')

    campaigns = Campaign.query

    if search:
        campaigns = campaigns.filter(
            Campaign.name.ilike(f'%{search}%') |
            Campaign.description.ilike(f'%{search}%')
        )

    if start_date:
        campaigns = campaigns.filter(Campaign.start_date >= start_date)

    if end_date:
        campaigns = campaigns.filter(Campaign.end_date <= end_date)

    if budget_order == 'lowest':
        campaigns = campaigns.order_by(Campaign.budget.asc())
    elif budget_order == 'highest':
        campaigns = campaigns.order_by(Campaign.budget.desc())

    campaigns = campaigns.all()
    user = User.query.get(session['user_id'])
    flagged_users = User.query.filter_by(flagged=True).all()

    return render_template('admin_dashboard.html', user=user, campaigns=campaigns, flagged_users=flagged_users)




@app.route('/campaign_admin_action/<int:id>/')
@auth_admin
def view_campaign_admin(id):
    campaign = Campaign.query.get_or_404(id)
    public_ad_requests = AdRequest.query.filter_by(campaign_id=id, privacy='Public').all()

    return render_template('campaign/view_out.html', campaign=campaign, public_ad_requests=public_ad_requests)


@app.route('/campaign_admin_action/<int:id>/delete', methods= ['GET', 'POST'])
@auth_admin
def delete_campaign_admin(id):
    campaign = Campaign.query.get_or_404(id)
    db.session.delete(campaign)
    db.session.commit()
    flash('Campaign has been deleted.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_stats')
@auth_admin
def admin_stats():
    # Get numbers of influencers and sponsors
    influencer_count = User.query.filter_by(role='influencer').count()
    sponsor_count = User.query.filter_by(role='sponsor').count()

    # Get the number of influencers per niche
    niches = db.session.query(Influencer.niche, func.count(Influencer.id)).group_by(Influencer.niche).all()

    # Get the number of sponsors per industry
    industries = db.session.query(Sponsor.industry, func.count(Sponsor.id)).group_by(Sponsor.industry).all()

    # Campaigns by year and month
    campaigns_by_year_month = db.session.query(
        extract('year', Campaign.start_date).label('year'),
        extract('month', Campaign.start_date).label('month'),
        func.count(Campaign.id).label('count')
    ).group_by('year', 'month').all()

    # Average budget for campaigns this month
    current_month = datetime.now().month
    current_year = datetime.now().year
    avg_budget_this_month = db.session.query(func.avg(Campaign.budget)).filter(
        extract('year', Campaign.start_date) == current_year,
        extract('month', Campaign.start_date) == current_month
    ).scalar()

    # Average payment to influencers this month
    avg_payment_to_influencers = db.session.query(func.avg(AdRequest.payment_amount)).join(Campaign).filter(
        extract('year', Campaign.start_date) == current_year,
        extract('month', Campaign.start_date) == current_month,
        AdRequest.status == 'Accepted'
    ).scalar()

    return render_template('admin_stats.html', 
                           influencer_count=influencer_count, 
                           sponsor_count=sponsor_count,
                           niches=niches,
                           industries=industries,
                           campaigns_by_year_month=campaigns_by_year_month,
                           avg_budget_this_month=avg_budget_this_month,
                           avg_payment_to_influencers=avg_payment_to_influencers)

    

@app.route('/profile_settings_admin')
@auth_admin
def profile_settings_admin():
    user = User.query.get(session['user_id'])
    return render_template('profile_settings_admin.html', user=user)

@app.route('/profile_settings_admin', methods=['POST'])
@auth_admin
def profile_settings_admin_post():
    username = request.form.get('username')
    name = request.form.get('name')
    currentpassword = request.form.get('currentpassword')
    password = request.form.get('password')
    
    if not username or not currentpassword or not password:
        flash('Fill all the information!')
        return redirect(url_for('profile_settings_admin'))
    
    user = User.query.get(session['user_id'])
    if not check_password_hash(user.password, currentpassword):
        flash ('Incorrect Passowrd!!')
        return redirect(url_for('profile_settings_admin'))
    
    if username is user.username:
        new_username = User.query.filter_by(username=username).first()
        if new_username:
            flash('Username already taken')
            return redirect(url_for('profile_settings_admin'))
        
    new_password = generate_password_hash(password)
    user.username = username
    user.password = new_password
    user.name = name
    db.session.commit()
    flash('Changes Successful','success')
    return redirect(url_for('profile_settings_admin'))



@app.route('/admin_ad_request')
@auth_admin
def admin_ad_request():
    status = request.args.get('status', '')
    min_payment = request.args.get('min_payment', '')
    max_payment = request.args.get('max_payment', '')

    ad_requests = AdRequest.query

    if status:
        ad_requests = ad_requests.filter(AdRequest.status == status)

    if min_payment:
        ad_requests = ad_requests.filter(AdRequest.payment_amount >= float(min_payment))

    if max_payment:
        ad_requests = ad_requests.filter(AdRequest.payment_amount <= float(max_payment))

    ad_requests = ad_requests.options(db.joinedload(AdRequest.influencer)).all()  # Eager load influencer
    user = User.query.get(session['user_id'])
    
    return render_template('campaign_admin_action/admin_ad_request.html', user=user, ad_requests=ad_requests)



@app.route('/campaign_admin_action/view_ad_request_admin/<int:id>')
@auth_admin
def view_ad_request_admin(id):
    ad_request = AdRequest.query.get_or_404(id)
    campaign = Campaign.query.get(ad_request.campaign_id)
    sponsor = Sponsor.query.get(campaign.sponsor_id)
    influencer = Influencer.query.get(ad_request.influencer_id)
    return render_template('campaign_admin_action/view_ad_request_admin.html', ad_request=ad_request, campaign=campaign, sponsor=sponsor, influencer=influencer)

@app.route('/delete_ad_request_admin/<int:id>', methods=['POST'])
@auth_admin
def delete_ad_request_admin(id):
    ad_request = AdRequest.query.get_or_404(id)
    db.session.delete(ad_request)
    db.session.commit()
    flash('Ad request has been deleted.')
    return redirect(url_for('admin_ad_request'))





@app.route('/campaign_admin_action/all_users', methods=['GET', 'POST'])
@auth_admin
def all_users():
    page = request.args.get('page', 1, type=int)
    user_type = request.args.get('user_type', 'all')
    flagged = request.args.get('flagged', 'all')

    query = User.query.filter(User.role != 'admin')

    if user_type == 'influencer':
        query = query.filter(User.role == 'influencer')
    elif user_type == 'sponsor':
        query = query.filter(User.role == 'sponsor')

    if flagged == 'flagged':
        query = query.filter(User.flagged == True)
    elif flagged == 'not_flagged':
        query = query.filter(User.flagged == False)

    users = query.paginate(page=page, per_page=10)

    return render_template('campaign_admin_action/all_users.html', users=users, user_type=user_type, flagged=flagged)


@app.route('/campaign_admin_action/view_user/<int:user_id>')
@auth_admin
def view_profile(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'influencer':
        influencer = Influencer.query.filter_by(id=user_id).first()
        return render_template('/campaign_admin_action/view_user.html', user=user, influencer=influencer)
    elif user.role == 'sponsor':
        sponsor = Sponsor.query.filter_by(id=user_id).first()
        return render_template('/campaign_admin_action/view_user.html', user=user, sponsor=sponsor)
    return redirect(url_for('admin_dashboard'))

@app.route('/campaign_admin_action/flagged/<int:user_id>', methods=['POST'])
@auth_admin
def flag_user(user_id):
    user = User.query.get_or_404(user_id)
    user.flagged = not user.flagged
    db.session.commit()
    flash(f'User {"flagged" if user.flagged else "unflagged"} successfully.')
    return redirect(url_for('all_users'))


def auth_sponsor(func):
    #using the functools' wraps: it assigns some different name for func so that 
    #flask dosent throw an error of maping same function for different address
    @wraps(func)  
    def inner_auth(*args, **kwargs):
        if 'user_id'not in session:
            flash('Please login first')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.role != 'sponsor':
            flash('You are not authorized to access this page')
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return inner_auth

@app.route('/profile/profile_sponsor/<int:id>')
@auth
def view_sponsor_profile(id):
    sponsor = Sponsor.query.get_or_404(id)
    campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).all()
    public_ad_requests = AdRequest.query.filter_by(sponsor_id=sponsor.id, privacy='Public').all()
    return render_template('profile/profile_sponsor.html', sponsor=sponsor, campaigns=campaigns, public_ad_requests=public_ad_requests)

@app.route('/profile/profile_influencers/<int:id>')
@auth
def view_influencer_profile(id):
    influencer = Influencer.query.get_or_404(id)
    ad_requests = AdRequest.query.filter_by(influencer_id=id, status='Accepted', privacy='Public').all()
    return render_template('profile/profile_influencers.html', influencer=influencer, ad_requests=ad_requests)




@app.route('/profile_sponsor')
@auth_sponsor
def profile_sponsor():
    user = User.query.get(session['user_id'])
    return render_template('profile/profile_sponsor.html', user=user)





### sponsor action on campaigns

@app.route('/campaigns_sponsor', methods=['GET', 'POST'])
@auth_sponsor
def campaigns_sponsor():
    user = User.query.get(session['user_id'])
    campaigns = Campaign.query.filter_by(sponsor_id=user.id).all()
    current_date = datetime.now().date()

    # Filtering
    progress_filter = request.args.get('progress_filter', '')
    name_filter = request.args.get('name_filter', '')

    filtered_campaigns = []

    for campaign in campaigns:
        total_days = (campaign.end_date - campaign.start_date).days
        elapsed_days = (current_date - campaign.start_date).days

        if total_days > 0:
            progress = (elapsed_days / total_days) * 100
            if progress < 0:
                progress = 0
            elif progress > 100:
                progress = 100
        else:
            progress = 100

        if progress == 100:
            progress_status = 'Done'
        elif progress == 0:
            progress_status = 'Not Started'
        else:
            progress_status = 'In Progress'

        if (not progress_filter or progress_status == progress_filter) and (not name_filter or name_filter.lower() in campaign.name.lower()):
            filtered_campaigns.append(campaign)

    return render_template('campaigns_sponsor.html', user=user, campaigns=filtered_campaigns, current_date=current_date, progress_filter=progress_filter, name_filter=name_filter)


@app.route('/view_ad_request/<int:id>', methods=['GET'])
@auth
def view_ad_request(id):
    user = User.query.get(session['user_id'])
    ad_request = AdRequest.query.get_or_404(id)
    return render_template('view_ad_request.html', ad_request=ad_request, user=user)

@app.route('/campaign/edit_ad_request/<int:id>', methods=['GET', 'POST'])
@auth_sponsor
def edit_ad_request(id):
    ad_request = AdRequest.query.get_or_404(id)
    if request.method == 'POST':
        privacy = request.form.get('privacy')
        message = request.form.get('message')
        requirements = request.form.get('requirements')
        payment = request.form.get('payment')
        user = User.query.get(session['user_id'])

        if not privacy or not message or not requirements or not payment:
            flash('All fields are required', 'danger')
            return redirect(url_for('edit_ad_request', id=id))

        try:
            payment = float(payment)  # Convert payment to float
        except ValueError:
            flash('Payment must be a number', 'danger')
            return redirect(url_for('edit_ad_request', id=id))
  
        if payment < 0:
            flash('Payment cannot be less than zero', 'danger')
            return redirect(url_for('edit_ad_request', id=id))
  
        sponsor_id = user.id  
       
        ad_request.campaign_id = ad_request.campaign_id
        ad_request.sponsor_id = sponsor_id
        ad_request.messages = message
        ad_request.requirements = requirements
        ad_request.payment_amount = payment
        ad_request.privacy = privacy
        ad_request.status = 'Pending'

        db.session.commit()
        flash('Ad Request Updated', 'success')

        return redirect(url_for('all_ad_request'))

    return render_template('campaign/edit_ad_request.html', ad_request=ad_request)




@app.route('/delete_ad_request/<int:id>', methods=['POST'])
@auth_sponsor
def delete_ad_request(id):
    user = User.query.get(session['user_id'])
    ad_request = AdRequest.query.get_or_404(id)
    db.session.delete(ad_request)
    db.session.commit()
    flash('Ad request deleted successfully!', 'success')
    return redirect(url_for('all_ad_request'))




@app.route('/profile_settings_sponsor')
@auth_sponsor
def profile_settings_sponsor():
    user = User.query.get(session['user_id'])
    sponsor = Sponsor.query.get(session['user_id'])
    return render_template('profile_settings_sponsor.html', user=user, sponsor=sponsor)


@app.route('/profile_settings_sponsor',  methods=['POST'])
@auth_sponsor
def profile_settings_sponsor_post():
    user = User.query.get(session['user_id'])
    username = request.form.get('username')
    name = request.form.get('name')
    industry = request.form.get('industry')
    currentpassword = request.form.get('currentpassword')
    password = request.form.get('password')

    if not username or not currentpassword or not password:
        flash('Fill all the information!')
        return redirect(url_for('profile_settings_sponsor'))

    user = User.query.get(session['user_id'])
    sponsor = Sponsor.query.get(user.id)
    

    # Validate username is unique
    existing_user = User.query.filter_by(username=username).first()
    if existing_user and existing_user.id != user.id:
        flash('Username already taken')
        return redirect(url_for('profile_settings_sponsor'))

    if not check_password_hash(user.password, currentpassword):
        flash('Incorrect Password!')
        return redirect(url_for('profile_settings_sponsor'))
    
    
    
    new_password = generate_password_hash(password)
    user.username = username
    user.name = name
    user.username = username
    user.password = new_password
    sponsor.username = username
    sponsor.company_name = name
    sponsor.industry = industry
    db.session.commit()
    flash('Changes Successful')
    return redirect(url_for('profile_settings_sponsor'))


@app.route('/campaign/<int:id>/')
@auth
def view_campaign(id):
    user = User.query.get(session['user_id'])
    campaign = Campaign.query.get_or_404(id)
    public_ad_requests = AdRequest.query.filter_by(campaign_id=id, privacy='Public').all()

    if campaign.sponsor_id == user.id:
        private_ad_requests = AdRequest.query.filter_by(campaign_id=id, privacy='Private').all()
        return render_template('campaign/view.html', campaign=campaign, current_date=datetime.now(), public_ad_requests=public_ad_requests, private_ad_requests=private_ad_requests, user=user)
    else:
        return render_template('campaign/view_out.html', campaign=campaign, current_date=datetime.now(), public_ad_requests=public_ad_requests, user=user)



@app.route('/campaign/add')
@auth_sponsor
def campaign_add():
    return render_template('campaign/add.html')


##process on ad_requests

@app.route('/all_ad_request')
@auth_sponsor
def all_ad_request():
  user = User.query.get(session['user_id'])
  
  page = request.args.get('page', 1, type=int)
  ad_requests = AdRequest.query.filter_by(sponsor_id=user.id, privacy='Private').paginate(page=page, per_page=10)
  campaign= Campaign.query.filter(Sponsor.id == user.id).all()
  return render_template('/campaign/all_ad_request.html', user=user, ad_requests=ad_requests, campaign=campaign)

@app.route('/all_ad_request_public')
@auth_sponsor
def all_ad_request_public():
  user = User.query.get(session['user_id'])
  
  page = request.args.get('page', 1, type=int)
  ad_requests = AdRequest.query.filter_by(sponsor_id=user.id, privacy='Public').paginate(page=page, per_page=10)
  #influencer= Influencer
  campaign= Campaign.query.filter(Sponsor.id == user.id).all()
  return render_template('campaign/all_ad_request_public.html', user=user, ad_requests=ad_requests, campaign=campaign)


@app.route('/ad_request/<int:id>')
@auth_sponsor
def ad_request(id):
    campaign = Campaign.query.get_or_404(id)
    if not campaign:
        flash("Id doesn't exist")
        return redirect(url_for(campaigns_sponsor))    
    return render_template('ad_request.html', campaign=campaign)


@app.route('/send_ad_request', methods=['POST'])
@auth_sponsor
def send_ad_request():
    influencer_id = request.form['influencer_id']
    campaign_id = request.form['campaign_id']
    messages = request.form['messages']
    requirements = request.form['requirements']
    payment_amount = request.form['payment_amount']
    user = User.query.get(session['user_id'])


    try:
            payment = float(payment)  # Convert payment to float
    except ValueError:
            flash('Payment must be a number')
            return redirect(url_for('ad_request', campaign_id=campaign_id))
  
    if payment < 0:
            flash('Payment cannot be less than zero')
            return redirect(url_for('ad_request',campaign_id=campaign_id))
  

    
    ad_request = AdRequest(
        campaign_id=campaign_id,
        influencer_id=influencer_id,
        sponsor_id=user.id,  
        messages=messages,
        requirements=requirements,
        payment_amount=payment_amount
    )
    db.session.add(ad_request)
    db.session.commit()
    flash('Ad request sent successfully!', 'success')
    return redirect(url_for('ad_request', campaign_id=campaign_id))

@app.route('/generate_ad_request/<int:id>', methods=['GET', 'POST'])
@auth_sponsor
def generate_ad_request(id):
    campaign = Campaign.query.get_or_404(id)
    if request.method == 'POST':
        privacy = request.form['privacy']
        message = request.form['message']
        requirements = request.form['requirements']
        payment = request.form['payment']
        user = User.query.get(session['user_id'])

        try:
            payment = float(payment)  # Convert payment to float
        except ValueError:
            flash('Payment must be a number')
            return redirect(url_for('ad_request', id=id))
  
        if payment < 0:
            flash('Payment cannot be less than zero')
            return redirect(url_for('ad_request', id=id))
  

        
        sponsor_id = user.id  
        ad_request = AdRequest(
            campaign_id=id,
            sponsor_id=sponsor_id,
            messages=message,
            requirements=requirements,
            payment_amount=payment,
            privacy=privacy,
            status='Pending'
        )
        db.session.add(ad_request)
        db.session.commit()
        flash('Ad Request Created')
        return redirect(url_for('campaigns_sponsor', id=id))

    





@app.route('/assign_influencer/<int:id>', methods=['GET', 'POST'])
@auth_sponsor
def assign_influencer(id):
    ad_request = AdRequest.query.get_or_404(id)
    
    if request.method == 'POST':
        influencer_id = request.form['influencer_id']
        ad_request.influencer_id = influencer_id
        ad_request.is_new_for_influencer = True
        db.session.commit()
        
        # Notify influencer (simplified)
        flash('Influencer assigned successfully!', 'success')
        return redirect(url_for('all_ad_request' if ad_request.privacy == 'Private' else 'all_ad_request_public'))
    
    search = request.args.get('search')
    niche = request.args.get('niche')
    
    query = Influencer.query
    if search:
        query = query.filter(Influencer.username.contains(search))
    if niche:
        query = query.filter(Influencer.niche.contains(niche))
        
    influencers = query.all()
    return render_template('assign_influencer.html', ad_request=ad_request, influencers=influencers)







@app.route('/campaign/add', methods=['POST'])
@auth_sponsor
def campaign_add_post():
    
    user = User.query.get(session['user_id'])
    name = request.form.get('campaignname')
    description = request.form.get('description')
    start_date = request.form.get('startdate')
    end_date = request.form.get('enddate')
    budget = request.form.get('budget')
    if not name or not description or not budget or not start_date or not end_date:
        flash('Fill all categories')
    try:
            budget = float(budget)  # Convert payment to float
    except ValueError:
            flash('Budget must be a Positive number')
            return redirect(url_for('campaign_add_post'))

    if budget < 0:
            flash('Budget cannot be less than zero')
            return redirect(url_for('campaign_add_post'))
    #Converting date strings to datetime.date objects
    start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
    end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
    sponsor_id= user.id
    campaign = Campaign(name=name, sponsor_id=sponsor_id, description=description, 
                        start_date=start_date, end_date=end_date, budget=budget)
    db.session.add(campaign)
    db.session.commit()
    flash(f'Added new campaign {name} to my campaigns')
    return redirect(url_for('campaigns_sponsor'))

@app.route('/campaign/<int:id>/edit')
@auth_sponsor
def campaign_edit(id):
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('This campaign does not exists')
    return render_template('campaign/edit.html', campaign=campaign)


@app.route('/campaign/<int:id>/edit', methods=['POST'])
@auth_sponsor
def campaign_edit_post(id):
    campaign = Campaign.query.get(id)
    if not campaign:
        flash('This campaign does not exists')
        return redirect(url_for('campaigns_sponsor'))
    
    user = User.query.get(session['user_id'])
    name = request.form.get('campaignname')
    sponsor_id = user.id
    description = request.form.get('description')
    start_date = request.form.get('startdate')
    end_date = request.form.get('enddate')
    budget = request.form.get('budget')

    if not name or not description or not budget or not start_date or not end_date:
        flash('Fill all categories')

    #Converting date strings to datetime.date objects
    start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
    end_date = datetime.strptime(end_date, '%Y-%m-%d').date()

    campaign.name=name
    campaign.sponsor_id=sponsor_id
    campaign.description=description
    campaign.start_date=start_date
    campaign.end_date=end_date
    campaign.budget=budget
                                           
    db.session.commit()
    flash(f'updated campaign {name} to my campaigns')
    return redirect(url_for('campaigns_sponsor'))






@app.route('/delete_campaign/<int:id>', methods=['POST'])
@auth_sponsor
def delete_campaign(id):
    campaign = Campaign.query.get_or_404(id)
    db.session.delete(campaign)
    db.session.commit()
    flash('Campaign has been deleted.')
    return redirect(url_for('campaigns_sponsor'))

## Influencer actions


@app.route('/received_ad_requests')
def received_ad_requests():
    user = User.query.get(session['user_id'])
    
    if user.role != 'influencer':
        flash('You are not authorized to view this page.', 'danger')
        return redirect(url_for('index'))
    
    ad_requests = AdRequest.query.filter_by(influencer_id=user.id).all()
    
    return render_template('received_ad_requests.html', ad_requests=ad_requests)





@app.route('/profile/personal_profile_influencer')
@auth
def influencer_profile():
    user_id = session.get('user_id')  # Assuming the user ID is stored in session
    user = User.query.get(user_id)
    
    if user is None or user.role != 'influencer':
        return "Unauthorized", 403
    
    influencer = Influencer.query.filter_by(username=user.username).first()
    if influencer is None:
        return "Influencer not found", 404
    
    current_month = datetime.now().month
    current_year = datetime.now().year
    
    # Get the ad requests associated with the influencer and filter by campaign dates
    ad_requests = AdRequest.query.join(Campaign).filter(
        AdRequest.influencer_id == influencer.id,
        AdRequest.status == 'Accepted',
        db.extract('month', Campaign.start_date) <= current_month,
        db.extract('month', Campaign.end_date) >= current_month,
        db.extract('year', Campaign.start_date) == current_year,
        db.extract('year', Campaign.end_date) == current_year
    ).all()

    total_payments = sum(ad_request.payment_amount for ad_request in ad_requests)
    
    return render_template('profile/personal_profile_influencer.html', user=user, influencer=influencer, ad_requests=ad_requests, total_payments=total_payments)


@app.route('/profile/personal_profile_sponsor')
@auth_sponsor
def sponsor_profile():
    user_id = session.get('user_id')  # Assuming the user ID is stored in session
    user = User.query.get(user_id)
    
    if user is None or user.role != 'sponsor':
        return "Unauthorized", 403
    
    sponsor = Sponsor.query.filter_by(username=user.username).first()
    if sponsor is None:
        return "Sponsor not found", 404
    
    current_month = datetime.now().month
    current_year = datetime.now().year
    
    # Get the campaigns associated with the sponsor and filter by the current month and year
    campaigns = Campaign.query.filter(
        Campaign.sponsor_id == sponsor.id,
        db.extract('month', Campaign.start_date) <= current_month,
        db.extract('month', Campaign.end_date) >= current_month,
        db.extract('year', Campaign.start_date) <= current_year,
        db.extract('year', Campaign.end_date) >= current_year
    ).all()

    # Calculate the budget spent this month
    budget_spent_this_month = sum(campaign.budget for campaign in campaigns)
    
    # Get the ad requests associated with the sponsor
    ad_requests = AdRequest.query.filter(
        AdRequest.sponsor_id == sponsor.id,
        AdRequest.status == 'Accepted'
    ).all()
    return render_template('profile/personal_profile_sponsor.html', user=user, sponsor=sponsor, ad_requests=ad_requests, campaigns=campaigns, budget_spent_this_month=budget_spent_this_month)
    
@app.route('/send_interest/<int:id>', methods=['POST'])
@auth
def send_interest(id):
    user = User.query.get(session['user_id'])
    ad_request = AdRequest.query.get_or_404(id)

    if user.role != 'influencer':
        flash('You are not authorized to perform this action.', 'danger')
        return redirect(url_for('home'))

    # Check if the influencer has already expressed interest in this ad request
    existing_interest = AdInterest.query.filter_by(ad_id=id, influencer_id=user.id).first()
    if existing_interest:
        flash('You have already expressed interest in this ad request.', 'info')
    else:
        # Create a new AdInterest entry
        new_interest = AdInterest(
            campaign_id=ad_request.campaign_id,
            ad_id=ad_request.id,
            influencer_id=user.id,
            sponsor_id=ad_request.sponsor_id,
            is_new_for_sponsor = True,
            privacy=ad_request.privacy,
            status='Interest Sent'
        )
        db.session.add(new_interest)
        db.session.commit()
        flash('Your interest has been sent successfully!', 'success')

    return redirect(url_for('home'))

@app.route('/received_ad_request/<int:id>', methods=['GET', 'POST'])
def received_ad_request(id):
    ad_request = AdRequest.query.get_or_404(id)
    user = User.query.get(session['user_id'])

    if user.id != ad_request.influencer_id:
        flash('You are not authorized to view this page.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        action = request.form['action']
        if action == 'accept':
            ad_request.status = 'Accepted'
        elif action == 'decline':
            ad_request.status = 'Declined'
        elif action == 'negotiate':
            new_payment_amount = request.form['new_payment_amount']
            if new_payment_amount:
                ad_request.payment_amount = float(new_payment_amount)
                ad_request.status = 'Negotiation'
                ad_request.is_new_for_influencer = False
                db.session.commit()
                flash('Negotiation request sent!', 'success')
                return redirect(url_for('received_ad_requests'))
        ad_request.is_new_for_influencer = False
        db.session.commit()
        flash('Action taken successfully!', 'success')
        return redirect(url_for('received_ad_requests'))

    return render_template('received_ad_request.html', ad_request=ad_request)

@app.route('/my_requests')
@auth
def my_requests():
    user = User.query.get(session['user_id'])
    if user.role != 'influencer':
        flash('You are not authorized to access this page')
        return redirect(url_for('home'))
           
    page = request.args.get('page', 1, type=int)
    requests_sent = AdRequest.query.join(Sponsor).filter(AdInterest.influencer_id == user.id, AdInterest.status== 'Interest Sent').paginate(page=page, per_page=10)
    return render_template('my_requests.html', requests_sent=requests_sent)


@app.route('/received_ad_interests_sponsor', methods=['GET'])
@auth_sponsor
def received_ad_interests_sponsor():
    user = User.query.get(session['user_id'])
    ad_interests = db.session.query(
        AdInterest.id.label('interest_id'),
        Campaign.id.label('campaign_id'),
        Campaign.name.label('campaign_name'),
        Sponsor.company_name.label('sponsor_name'),
        AdRequest.messages.label('ad_message'),
        AdRequest.requirements.label('ad_requirements'),
        AdRequest.status.label('ad_status'),
        AdRequest.payment_amount.label('ad_payment'),
        Influencer.name.label('influencer_name')
    ).join(AdRequest, AdInterest.ad_id == AdRequest.id) \
     .join(Campaign, AdInterest.campaign_id == Campaign.id) \
     .join(Influencer, AdInterest.influencer_id == Influencer.id) \
     .join(Sponsor, AdInterest.sponsor_id == Sponsor.id) \
     .filter(AdInterest.sponsor_id == user.id, AdInterest.status == 'Interest Sent', AdInterest.is_new_for_sponsor == True).all()

    return render_template('received_ad_interests_sponsor.html', ad_interests=ad_interests)



@app.route('/accept_ad_interest/<int:id>', methods=['POST'])
@auth_sponsor
def accept_ad_interest(id):
    ad_interest = AdInterest.query.get_or_404(id)
    if ad_interest.sponsor_id != session['user_id']:
        flash('You are not authorized to perform this action', 'danger')
        return redirect(url_for('received_ad_interests_sponsor'))
    
    ad_interest.status = 'Accepted'

    ad_request = AdRequest.query.get(ad_interest.ad_id)
    if ad_request:
        ad_request.influencer_id = ad_interest.influencer_id
        ad_request.status = 'Accepted'
        ad_interest.status = 'Accepted'
        ad_request.privacy = ad_interest.privacy

    # Commit the changes to the database
    db.session.commit()
    flash('Ad interest and ad request accepted successfully', 'success')
    return redirect(url_for('received_ad_interests_sponsor'))


@app.route('/reject_ad_interest/<int:id>', methods=['POST'])
@auth_sponsor
def reject_ad_interest(id):
    ad_interest = AdInterest.query.get_or_404(id)
    if ad_interest.sponsor_id != session['user_id']:
        flash('You are not authorized to perform this action', 'danger')
        return redirect(url_for('received_ad_interests_sponsor'))
    
    ad_interest.status = 'Rejected'
    db.session.commit()
    flash('Ad interest rejected successfully', 'success')
    return redirect(url_for('received_ad_interests_sponsor'))



@app.route('/accept_negotiation/<int:id>', methods=['POST'])
@auth_sponsor
def accept_negotiation(id):
    ad_request = AdRequest.query.get_or_404(id)
    user = User.query.get(session['user_id'])

    if user.id != ad_request.sponsor_id:
        flash('You are not authorized to perform this action', 'danger')
        return redirect(url_for('all_ad_request'))

    if ad_request.status == 'Negotiation':
        ad_request.status = 'Accepted'
        db.session.commit()
        flash('Negotiation accepted successfully', 'success')
    else:
        flash('Ad request is not in negotiation status', 'danger')

    return redirect(url_for('all_ad_request'))


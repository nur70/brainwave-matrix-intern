from flask import Flask, render_template, request
import requests
import whois
from bs4 import BeautifulSoup
import tldextract
import datetime

app = Flask(__name__)

BLACKLIST = {'phishing.com', 'malicious-website.com'}

def is_blacklisted(url):
    domain = tldextract.extract(url).domain
    return domain in BLACKLIST

def has_https(url):
    return url.startswith('https://')

def check_url(url):
    if is_blacklisted(url):
        return "Phishing detected: URL is in the blacklist."
    if not has_https(url):
        return "Warning: URL does not use HTTPS."
    try:
        domain_info = whois.whois(tldextract.extract(url).domain)
        if domain_info.creation_date is not None:
            age = (datetime.datetime.now() - domain_info.creation_date).days
            if age < 30:
                return "Warning: Domain is newly registered."
    except Exception as e:
        return f"Error fetching whois data: {e}"
    
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        phishing_keywords = ['login', 'update', 'confirm', 'account', 'secure']
        if any(keyword in soup.get_text().lower() for keyword in phishing_keywords):
            return "Warning: Page contains suspicious keywords."
    except requests.exceptions.RequestException as e:
        return f"Error accessing the URL: {e}"

    return "URL appears to be safe."

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    result = check_url(url)
    return render_template('result.html', url=url, result=result)

if __name__ == "__main__":
    app.run(debug=True)

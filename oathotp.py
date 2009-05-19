from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app

class OtpPage(webapp.RequestHandler):
  def get(self):
    self.response.headers['Content-Type'] = 'text/plain'
    self.response.out.write("otp")

class AdminPage(webapp.RequestHandler):
  def get(self):
    self.response.headers['Content-Type'] = 'text/plain'
    self.response.out.write("auth")

class MainPage(webapp.RequestHandler):
  def get(self):
#    html_content = "stuff"
    html_content = """
Validate OATH token - connect to /otp?serial=[serial]&pin=[pin]
response will be success or error

"""
    self.response.headers['Content-Type'] = 'text/plain'
    self.response.out.write('Hello, webapp World!\n')
    self.response.out.write(html_content)
    self.response.out.write(self.request.get('content'))

application = webapp.WSGIApplication(
                                     [('/otp', OtpPage),
                                     ('/admin', AdminPage),
                                     ('/', MainPage)],
                                     debug=True)

def main():
  run_wsgi_app(application)

if __name__ == "__main__":
  main()

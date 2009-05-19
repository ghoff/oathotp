from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext import db

class HotpData(db.Model):
  id = db.IntegerProperty(required=True)
  serialno = db.StringProperty(required=True)
  salt = db.ByteStringProperty(required=True)
  secret = db.ByteStringProperty(required=True)

class OtpPage(webapp.RequestHandler):
  def get(self):
    self.response.headers['Content-Type'] = 'text/plain'
    self.response.out.write("otp")

class AdminPage(webapp.RequestHandler):
  def get(self):
    self.response.headers['Content-Type'] = 'text/html'
    user = users.get_current_user()
    if user and not users.is_current_user_admin():
      self.response.out.write("<html><head></head><body>\n")
      self.response.out.write("Only admin users allowed\n")
      self.response.out.write("<br><a href=%s>Logout</a>" % users.create_logout_url(self.request.uri))
      self.response.out.write("</body></html>")
    elif user and users.is_current_user_admin():
      self.response.out.write("<html><head></head><body>\n")
      self.response.out.write("add a new value\n")
      self.response.out.write("""
            <form action="/admin" method="post">
	    <table>
	      <tr><td>id</td><td><input name="id" size=20></td></tr>
              <tr><td>serialno</td><td><input name="serialno" size=20></td></tr>
              <tr><td>salt</td><td><input name="salt" size=20></td></tr>
              <tr><td>secret</td><td><input name="secret" size=20></td></tr>
	    </table>
              <input type="submit" value="add entry"></div>
            </form>""")

      self.response.out.write("<br><a href=%s>Logout</a>" % users.create_logout_url(self.request.uri))
      self.response.out.write("</body></html>")
    else:
      self.redirect(users.create_login_url(self.request.uri))
#    if self.request.get('id'):
#      querys = HotpData.all()
#      querys.filter('id =', self.request.get('id'))
#      for query in querys:
#        if query.id:
#	  self.response.out.write('%s %s\n' % query.id, query.serialno)

  def post(self):
    user = users.get_current_user()
    if user and users.is_current_user_admin():
      self.response.headers['Content-Type'] = 'text/plain'
      id=self.request.get('id')
      serialno=self.request.get('serialno')
      salt=self.request.get('salt')
      secret=self.request.get('secret')
      self.response.out.write("id = %s\n" % id)
      self.response.out.write("serialno = %s\n" % serialno)
      self.response.out.write("salt = %s\n" % salt)
      self.response.out.write("secret = %s\n" % secret)
      #hdata = HotpData(id=self.request.get('id'),
      #  serialno=self.request.get('serialno'),
      #  salt=self.request.get('salt'),
      #  secret=self.request.get('secret'))
      #hdata.put()
    else:
      self.response.out.write("Access Denied.")



class MainPage(webapp.RequestHandler):
  def get(self):
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
                                     debug=False)

def main():
  run_wsgi_app(application)

if __name__ == "__main__":
  main()

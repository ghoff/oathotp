from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext import db
import hotpy
import os
import binascii

class HotpData(db.Model):
  id = db.StringProperty(required=True)
  serialno = db.StringProperty(required=True)
  iv = db.StringProperty(required=True)
  seed = db.StringProperty(required=True)
  sequence = db.IntegerProperty(required=True)
  otpdigits = db.IntegerProperty(required=True)

class OtpPage(webapp.RequestHandler):
  def get(self):
    self.response.headers['Content-Type'] = 'text/plain'
    if self.request.get('id'):
      querys = HotpData.all()
      querys.filter('id =', self.request.get('id'))
      if querys.count() == 1:
        for query in querys:
          self.response.out.write("%s %s\n" % (query.id, query.serialno))
	  hconfig = dict()
	  #fix this later, extract pin from full pin+otp
	  hconfig['pincode'] = self.request.get('pin')
	  hconfig['seed'] = query.seed
	  hconfig['iv'] = query.iv
	  hconfig['counter'] = query.sequence
	  hconfig['digits'] = query.otpdigits
	  # need to fix generator to work correctly with bad pin
	  gen = hotpy.OTPGenerator(hconfig)
          self.response.out.write(gen.getOTP())
	  query.sequence = query.sequence + 1
	  query.put()

      elif querys.count() > 1:
        self.response.out.write("Error: mutiple entries not yet supported\n")
      else:
        self.response.out.write("Error: invalid ID\n")
    else:
        self.response.out.write("Must include id request\n")

class AdminPage(webapp.RequestHandler):
  def get(self):
    self.response.headers['Content-Type'] = 'text/html'
    self.response.out.write("<html><head></head><body>\n")
    user = users.get_current_user()
    if user and not users.is_current_user_admin():
      self.response.out.write("Only admin users allowed\n")
      self.response.out.write("<br><a href=%s>Logout</a>" % users.create_logout_url(self.request.uri))
      self.response.out.write("</body></html>")
    elif user and users.is_current_user_admin():
      self.response.out.write("add a new value\n")
      self.response.out.write("""
            <form action="/admin" method="post">
	    <table>
	      <tr><td>id</td><td><input name="id" size=20></td></tr>
              <tr><td>serialno</td><td><input name="serialno" size=20></td></tr>
              <tr><td>sequence</td><td><input name="sequence" size=16></td></tr>
              <tr><td>pin</td><td><input name="pin" size=16></td></tr>
              <tr><td>seed</td><td><input name="seed" size=64></td></tr>
              <tr><td>otp digits</td><td><input name="otpdigits" size=64></td></tr>
	    </table>
              <input type="submit" value="add entry"></div>
            </form>""")
      self.response.out.write("<br><a href=%s>Logout</a>" % users.create_logout_url(self.request.uri))
    else:
      self.redirect(users.create_login_url(self.request.uri))
      self.response.out.write("<br><a href=%s>Login</a>" % users.create_login_url(self.request.uri))
    self.response.out.write("</body></html>")

  def post(self):
    user = users.get_current_user()
    if user and users.is_current_user_admin():
      self.response.headers['Content-Type'] = 'text/plain'
      id=self.request.get('id')
      serialno=self.request.get('serialno')
      sequence=self.request.get('sequence')
      pin=self.request.get('pin')
      seed=self.request.get('seed')
      otpdigits=self.request.get('otpdigits')

      iv = binascii.b2a_hex(os.urandom(16))
      hconfig = {}
      hconfig['pincode'] = pin
      hconfig['seed'] = seed
      hconfig['iv'] = iv
      encseed = hotpy.OTPGenerator(hconfig)
      eseed = encseed.cryptSeed()

      self.response.out.write("id = %s\n" % id)
      self.response.out.write("serialno = %s\n" % serialno)
      self.response.out.write("sequence = %s\n" % sequence)
      self.response.out.write("pin = %s\n" % pin)
      self.response.out.write("seed = %s\n" % seed)
      self.response.out.write("iv = %s\n" % iv)
      self.response.out.write("eseed = %s\n" % eseed)
      self.response.out.write("otp digits = %s\n" % otpdigits)
      hdata = HotpData(id=id,
        serialno=serialno,
        iv=iv,
        seed=eseed,
        sequence=int(sequence),
	otpdigits=int(otpdigits))
      hdata.put()
    else:
      self.response.out.write("Access Denied.")

class MainPage(webapp.RequestHandler):
  def get(self):
    html_content = """
Validate OATH token - connect to /otp?id=[id]&pin=[pin]
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

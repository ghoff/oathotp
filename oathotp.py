from google.appengine.ext import db
from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.ext.webapp.util import run_wsgi_app
import os
import hotpy
import binascii
import string

class HotpData(db.Model):
  id = db.StringProperty(required=True)
  serialno = db.StringProperty(required=True)
  iv = db.StringProperty(required=True)
  seed = db.StringProperty(required=True)
  sequence = db.IntegerProperty(required=True)
  otpdigits = db.IntegerProperty(required=True)

class Utility():
  def calc_otp(self, request):
    success = 0
    allowed = string.ascii_letters + string.digits + "-_"
    delete_table = string.maketrans(allowed, ' ' * len(allowed))
    table = string.maketrans('', '')
    id = str(request.get('id'))
    id = id.translate(table, delete_table)
    querys = HotpData.all()
    querys.filter('id =', id)
    if querys.count() == 1:
      for query in querys:
        hconfig = dict()
        #extract pin from full pin+otp
        tmppin = str(request.get('pin'))
        tmppin = tmppin.translate(table, delete_table)
        pinlen = len(tmppin)
        if pinlen < query.otpdigits:
          out = "status=BAD_PIN"
          return(out)
        key = tmppin[:pinlen - query.otpdigits]
        pin = tmppin[pinlen - query.otpdigits:]
        hconfig['pincode'] = key
        hconfig['seed'] = query.seed
        hconfig['iv'] = query.iv
        hconfig['counter'] = query.sequence
        hconfig['digits'] = query.otpdigits
        # need to fix generator to work correctly with bad pin
        gen = hotpy.OTPGenerator(hconfig)
        for loop in range(0, 10):
          genpin = gen.getOTP()
          if genpin == pin:
             success = 1
             break
        if success:
          out = "status=OK"
          query.sequence = query.sequence + loop + 1
          query.put()
        else:
          out = "status=FAILED"
    elif querys.count() > 1:
      out = "status=EXTENDED_ERROR\ninfo=Mutiple entries not yet supported"
    else:
      out = "status=BAD_ID"
    return(out)

class OtpPage(webapp.RequestHandler):
  def get(self):
    self.response.headers['Content-Type'] = 'text/plain'
    if self.request.get('id') and self.request.get('pin'):
      out = Utility().calc_otp(self.request)
      self.response.out.write("%s\n" % out)
    else:
      self.response.out.write("status=MISSING_PARAMETER\n")


class DemoPage(webapp.RequestHandler):
  def get(self):
    self.response.headers['Content-Type'] = 'text/html'
    self.response.out.write("<html><head></head><body>\n")
    self.response.out.write("""
    <form action="/demo" method="post">
    <table>
      <tr><td>id</td><td><input name="id" type="text"size=20></td></tr>
      <tr><td>otp</td><td><input name="pin" type="password" size=20></td></tr>
    </table>
    <input type="submit" value="test"></div>
    </form>""")
    self.response.out.write("</body></html>")

  def post(self):
    self.response.headers['Content-Type'] = 'text/plain'
    if self.request.get('id') and self.request.get('pin'):
      out = Utility().calc_otp(self.request)
      self.response.out.write("%s\n" % out)
    else:
      self.response.out.write("status=MISSING_PARAMETER\n")


class AdminPage(webapp.RequestHandler):
  def get(self):
    admin = 0
    login = 0
    self.response.headers['Content-Type'] = 'text/html'
    user = users.get_current_user()
    logout_url = users.create_logout_url(self.request.uri)
    login_url = users.create_login_url(self.request.uri)
    if user and not users.is_current_user_admin():
      login = 1
    elif user and users.is_current_user_admin():
      login = 1
      admin = 1
    else:
      admin = 0
      login = 0
    template_values = {
      'login' : login,
      'admin' : admin,
      'login_url' : login_url,
      'logout_url' : logout_url,
      }
    path = os.path.join(os.path.dirname(__file__), 'admin.html')
    self.response.out.write(template.render(path, template_values))


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
    self.response.headers['Content-Type'] = 'text/html'
    path = os.path.join(os.path.dirname(__file__), "index.html")
    self.response.out.write(template.render(path,None))

application = webapp.WSGIApplication(
                                     [('/otp', OtpPage),
                                     ('/admin', AdminPage),
                                     ('/demo', DemoPage),
                                     ('/', MainPage)],
                                     debug=False)

def main():
  run_wsgi_app(application)

if __name__ == "__main__":
  main()
